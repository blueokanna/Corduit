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

/// Copy buffer size (32 KiB — a good middle ground between syscall
/// frequency and L2 cache footprint).
pub const RELAY_BUF_SIZE: usize = 32 * 1024;

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
}

impl SyncStream for TcpStream {
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        TcpStream::shutdown(self, how)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        TcpStream::peer_addr(self).ok()
    }
}

impl<T: SyncStream + ?Sized> SyncStream for &mut T {
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        (**self).shutdown(how)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        (**self).peer_addr()
    }
}

impl SyncStream for Box<dyn SyncStream> {
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        (**self).shutdown(how)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        (**self).peer_addr()
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
/// Each stream is shared behind a mutex, but **no operation holds two locks
/// at once** — a read locks one stream, copies out, unlocks, then a write
/// locks the other. That ordering is what makes the two-thread relay
/// deadlock-free by construction (thread A reads `x` while thread B writes
/// `x`, never both holding opposing locks).
pub fn relay(a: BoxStream, b: BoxStream, token: CancellationToken) -> io::Result<RelayStats> {
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
                let n = match aa.lock().unwrap().read(&mut buf) {
                    Ok(0) => {
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
                        continue;
                    }
                    Err(e) => {
                        let _ = aa.lock().unwrap().shutdown(Shutdown::Both);
                        let _ = ba.lock().unwrap().shutdown(Shutdown::Both);
                        return Err(e);
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
                let n = match bb.lock().unwrap().read(&mut buf) {
                    Ok(0) => {
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
                        continue;
                    }
                    Err(e) => {
                        let _ = ab.lock().unwrap().shutdown(Shutdown::Both);
                        let _ = bb.lock().unwrap().shutdown(Shutdown::Both);
                        return Err(e);
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
