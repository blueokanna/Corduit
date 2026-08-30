//! Synchronous duplex streams and the bidirectional relay.
//!
//! [`SyncStream`] is the canonical transport trait of the synchronous
//! engine — the replacement for the old tokio `AsyncReadWrite`. Every
//! stream Corduit relays through (plain TCP, courierust TLS, WebSocket)
//! implements it, so the relay and the outbound handlers stay agnostic to
//! the transport underneath.
//!
//! [`relay`] is the heart of every proxy connection: two dedicated threads,
//! one per direction, each doing a bounded blocking copy with proper
//! half-close semantics.

use crate::common::cancel::CancellationToken;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Copy buffer size (32 KiB — a good middle ground between syscall
/// frequency and L2 cache footprint).
pub const RELAY_BUF_SIZE: usize = 32 * 1024;

/// Read timeout the relay installs on both transports before starting its
/// copy threads.
///
/// The relay's two threads share each stream behind a mutex (boxed streams
/// need `&mut` for both read and write). If a thread blocked in `read()`
/// while holding that mutex indefinitely, the *other* thread could never
/// write to the same stream — a lock-ordering deadlock the moment one side
/// has data while the other is idle. A short read timeout bounds every lock
/// hold, so the mutex is guaranteed to be released within one poll interval;
/// the other direction's writes then get through within that window. This is
/// the same cadence the old blocking bridge used (20 ms), and it costs
/// nothing on a busy connection (reads return as soon as data arrives).
pub const RELAY_READ_POLL: Duration = Duration::from_millis(25);

/// Lock-fairness yield after an idle relay poll (see [`RELAY_READ_POLL`]).
///
/// The relay's two threads share each stream behind a `std::sync::Mutex`
/// whose handoff is not fair: after a read times out (idle), a thread
/// re-locks its source stream almost instantly, which can starve the
/// opposite direction's writes for seconds on Linux. Sleeping for this
/// window with the lock released lets the other direction write through
/// within a bounded time.
pub const RELAY_POLL_YIELD: Duration = Duration::from_millis(2);

/// A boxed synchronous duplex byte stream — the engine's canonical relay
/// type.
pub type BoxStream = Box<dyn SyncStream>;

/// A synchronous duplex byte stream with peer metadata and half-close.
pub trait SyncStream: Read + Write + Send {
    /// Shut down the read, write or both halves of the transport, waking
    /// any operation blocked on the other thread. Transports that cannot
    /// half-close (TLS, WebSocket) leave this as a no-op.
    fn shutdown(&self, how: Shutdown) -> io::Result<()>;

    /// The remote address, if the transport exposes one.
    fn peer_addr(&self) -> Option<SocketAddr> {
        None
    }

    /// Bound how long a blocking read can hold the stream (see
    /// [`RELAY_READ_POLL`]). Transports without a socket underneath leave
    /// this as a no-op.
    fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    /// Bound how long a blocking write can block. Default no-op.
    fn set_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}

impl SyncStream for TcpStream {
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        TcpStream::shutdown(self, how)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        TcpStream::peer_addr(self).ok()
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, timeout)
    }
}

impl<T: SyncStream + ?Sized> SyncStream for &mut T {
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        (**self).shutdown(how)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        (**self).peer_addr()
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        (**self).set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        (**self).set_write_timeout(timeout)
    }
}

impl SyncStream for Box<dyn SyncStream> {
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        (**self).shutdown(how)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        (**self).peer_addr()
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        (**self).set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        (**self).set_write_timeout(timeout)
    }
}

/// Statistics for one [`relay`] run.
#[derive(Debug, Default, Clone, Copy)]
pub struct RelayStats {
    /// Bytes copied client → server.
    pub up: u64,
    /// Bytes copied server → client.
    pub down: u64,
}

/// Copy `src` → `dst` until EOF on `src`, an error, or cancellation.
///
/// On EOF the write half of `dst` is shut down (half-close) so the peer
/// observes end-of-stream immediately while the reverse direction keeps
/// flowing. `WouldBlock`/`TimedOut` are treated as "nothing happened" —
/// the loop re-checks cancellation and keeps going.
#[cfg_attr(not(test), allow(dead_code))]
fn copy_one_way(
    src: &mut dyn Read,
    dst: &mut dyn Write,
    dst_shutdown: &mut dyn FnMut(),
    token: &CancellationToken,
    stats: &mut u64,
) -> io::Result<()> {
    let mut buf = vec![0u8; RELAY_BUF_SIZE];
    loop {
        if token.is_cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        match src.read(&mut buf) {
            Ok(0) => {
                // Peer closed cleanly: propagate EOF to the other side.
                dst_shutdown();
                return Ok(());
            }
            Ok(n) => {
                dst.write_all(&buf[..n])?;
                *stats += n as u64;
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Bidirectionally relay two duplex streams on dedicated threads.
///
/// Two copy threads — one per direction — each doing a bounded blocking
/// copy. When a direction reaches EOF it half-closes the opposite peer; on
/// error or cancellation both transports are shut down so the peer thread
/// wakes with an error and exits promptly.
///
/// The copy threads are dedicated OS threads (not pool workers) so a relay
/// can never starve the work-stealing pool of handshake capacity; the
/// number of concurrent relays is bounded upstream by
/// [`crate::common::exec::SessionGate`].
///
/// # Locking
///
/// Each stream is shared behind a mutex (boxed streams need `&mut` for both
/// read and write), and the relay installs a short read timeout on both
/// transports before starting, so **no thread ever holds a stream's lock
/// across an unbounded block**. A read that would wait forever returns
/// `WouldBlock`/`TimedOut` after [`RELAY_READ_POLL`] and releases the lock;
/// the other direction's write then gets through within that window. This is
/// what makes the two-thread relay deadlock-free by construction.
///
/// Because `std::sync::Mutex` handoff is not fair, an idle direction that
/// re-locks immediately after an idle poll would starve the opposite
/// direction's writes; each thread therefore drops the source stream's lock
/// and yields for [`RELAY_POLL_YIELD`] before re-polling.
pub fn relay(a: BoxStream, b: BoxStream, token: CancellationToken) -> io::Result<RelayStats> {
    // Bound every blocking read (see RELAY_READ_POLL) and give writes a
    // generous ceiling so a stalled peer cannot pin a lock forever.
    let _ = a.set_read_timeout(Some(RELAY_READ_POLL));
    let _ = b.set_read_timeout(Some(RELAY_READ_POLL));
    let _ = a.set_write_timeout(Some(Duration::from_secs(60)));
    let _ = b.set_write_timeout(Some(Duration::from_secs(60)));

    let a = Arc::new(Mutex::new(a));
    let b = Arc::new(Mutex::new(b));
    let stats = Arc::new(Mutex::new(RelayStats::default()));

    // Thread 1: a → b. On EOF of a, half-close b's write half.
    let ta = token.clone();
    let sa = stats.clone();
    let aa = a.clone();
    let ba = b.clone();
    let t1 = std::thread::Builder::new()
        .name("corduit-relay-up".into())
        .spawn(move || {
            let mut buf = vec![0u8; RELAY_BUF_SIZE];
            loop {
                if ta.is_cancelled() {
                    let _ = aa.lock().unwrap().shutdown(Shutdown::Both);
                    let _ = ba.lock().unwrap().shutdown(Shutdown::Both);
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
                }
                let n = {
                    let mut guard = aa.lock().unwrap();
                    match guard.read(&mut buf) {
                        Ok(0) => {
                            drop(guard);
                            let _ = ba.lock().unwrap().shutdown(Shutdown::Write);
                            return Ok(());
                        }
                        Ok(n) => n,
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) =>
                        {
                            // Release the source stream's lock BEFORE yielding
                            // so the opposite direction can write through (the
                            // std mutex handoff is not fair).
                            drop(guard);
                            std::thread::sleep(RELAY_POLL_YIELD);
                            continue;
                        }
                        Err(e) => {
                            drop(guard);
                            let _ = ba.lock().unwrap().shutdown(Shutdown::Both);
                            let _ = aa.lock().unwrap().shutdown(Shutdown::Both);
                            return Err(e);
                        }
                    }
                };
                if let Err(e) = ba.lock().unwrap().write_all(&buf[..n]) {
                    let _ = aa.lock().unwrap().shutdown(Shutdown::Both);
                    let _ = ba.lock().unwrap().shutdown(Shutdown::Both);
                    return Err(e);
                }
                sa.lock().unwrap().up += n as u64;
            }
        })?;

    // Thread 2: b → a. On EOF of b, half-close a's write half.
    let tb = token.clone();
    let sd = stats.clone();
    let ab = a.clone();
    let bb = b.clone();
    let t2 = std::thread::Builder::new()
        .name("corduit-relay-down".into())
        .spawn(move || {
            let mut buf = vec![0u8; RELAY_BUF_SIZE];
            loop {
                if tb.is_cancelled() {
                    let _ = ab.lock().unwrap().shutdown(Shutdown::Both);
                    let _ = bb.lock().unwrap().shutdown(Shutdown::Both);
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
                }
                let n = {
                    let mut guard = bb.lock().unwrap();
                    match guard.read(&mut buf) {
                        Ok(0) => {
                            drop(guard);
                            let _ = ab.lock().unwrap().shutdown(Shutdown::Write);
                            return Ok(());
                        }
                        Ok(n) => n,
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) =>
                        {
                            drop(guard);
                            std::thread::sleep(RELAY_POLL_YIELD);
                            continue;
                        }
                        Err(e) => {
                            drop(guard);
                            let _ = ab.lock().unwrap().shutdown(Shutdown::Both);
                            let _ = bb.lock().unwrap().shutdown(Shutdown::Both);
                            return Err(e);
                        }
                    }
                };
                if let Err(e) = ab.lock().unwrap().write_all(&buf[..n]) {
                    let _ = ab.lock().unwrap().shutdown(Shutdown::Both);
                    let _ = bb.lock().unwrap().shutdown(Shutdown::Both);
                    return Err(e);
                }
                sd.lock().unwrap().down += n as u64;
            }
        })?;

    let r1 = t1
        .join()
        .map_err(|_| io::Error::other("relay thread panicked"))?;
    let r2 = t2
        .join()
        .map_err(|_| io::Error::other("relay thread panicked"))?;

    // A cancelled relay or an error on either direction is a failure; EOF
    // on both sides is a clean teardown.
    if token.is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "relay cancelled",
        ));
    }
    r1.and(r2)?;
    let stats = Arc::try_unwrap(stats)
        .map(|m| m.into_inner().unwrap())
        .unwrap_or_default();
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn copy_one_way_half_closes_on_eof() {
        let token = CancellationToken::new();
        let mut src = Cursor::new(b"hello world".to_vec());
        let mut dst = Cursor::new(Vec::new());
        let mut closed = false;
        let mut stats = 0u64;
        {
            let mut hook = || closed = true;
            copy_one_way(&mut src, &mut dst, &mut hook, &token, &mut stats).unwrap();
        }
        assert!(closed);
        assert_eq!(stats, 11);
        assert_eq!(dst.into_inner(), b"hello world");
    }

    #[test]
    fn copy_one_way_stops_on_cancel() {
        let token = CancellationToken::new();
        token.cancel();
        let mut src = Cursor::new(vec![0u8; 1024]);
        let mut dst = Cursor::new(Vec::new());
        let mut hook = || {};
        let mut stats = 0u64;
        let res = copy_one_way(&mut src, &mut dst, &mut hook, &token, &mut stats);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::Interrupted);
    }
}
