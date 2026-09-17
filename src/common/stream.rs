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

/// Read timeout the relay installs on a **serialized** side — one that has no
/// [`SharedStream`] and therefore has to hand a lock over.
///
/// A side whose read and write need `&mut` on the same object is shared behind
/// a mutex. If a thread blocked in `read()` while holding that mutex
/// indefinitely, the *other* thread could never write to the same stream — a
/// lock-ordering deadlock the moment one side has data while the other is idle.
/// A short read timeout bounds every lock hold, so the mutex is guaranteed to
/// be released within one interval and the other direction's write gets through
/// within that window. This is what makes the serialized relay deadlock-free by
/// construction.
///
/// The cost is the reason the concurrent path exists: this interval is a
/// poll in disguise, so it wakes both directions forever *and* delays the
/// opposite direction's write by up to its full length. It is only paid where
/// the transport leaves no alternative.
pub const RELAY_READ_POLL: Duration = Duration::from_millis(25);

/// Lock-fairness yield after an idle poll on a serialized side (see
/// [`RELAY_READ_POLL`]).
///
/// `std::sync::Mutex` handoff is not fair: after a read times out, a thread
/// re-locks its source stream almost instantly, which can starve the opposite
/// direction's writes for seconds on Linux. Sleeping for this window with the
/// lock released lets the other direction write through within a bounded time.
pub const RELAY_POLL_YIELD: Duration = Duration::from_millis(2);

/// Ceiling on a single relay write, on both the concurrent and the serialized
/// path.
///
/// A relay writes with the peer's backpressure, so a write is allowed to block
/// — but not forever: a peer that has stopped reading for this long has gone
/// away without saying so, and the connection is better torn down than held.
pub const RELAY_WRITE_TIMEOUT: Duration = Duration::from_secs(60);

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
    ///
    /// Only consulted on the serialized path: a transport that offers a
    /// [`shared_handle`](Self::shared_handle) does not need its reads bounded
    /// at all.
    fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    /// Bound how long a blocking write can block. Default no-op.
    fn set_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    /// A handle that can be read, written and shut down from more than one
    /// thread at the same time — the transport's own concurrency, not a lock
    /// on top of it.
    ///
    /// This is what lets [`relay`] stop serializing. Sharing one `&mut` stream
    /// between the two directions is the reason the relay has to bound every
    /// read; a handle is the same transport without that constraint, so a
    /// direction can park in a read for as long as it likes while the other
    /// writes.
    ///
    /// Returning `None` (the default) keeps the serialized path, which is the
    /// right answer for any transport whose read and write genuinely share
    /// mutable state — a TLS or AEAD record layer, a WebSocket frame codec.
    fn shared_handle(&self) -> Option<SharedStream> {
        None
    }
}

/// A transport that supports concurrent reading, writing and shutdown.
///
/// Every method takes `&self` on purpose: the point is that two relay
/// directions can hold the same handle and use it at the same time. An
/// implementation must therefore be `Send + Sync` and must not hold a lock
/// across anything that can block on the peer.
pub trait StreamHandle: Send + Sync {
    /// Read whatever is available. May block.
    fn read_shared(&self, buf: &mut [u8]) -> io::Result<usize>;

    /// Write what the peer will accept; a short write is not an error.
    fn write_shared(&self, buf: &[u8]) -> io::Result<usize>;

    /// Release anything blocked on this transport.
    fn shutdown_shared(&self, how: Shutdown) -> io::Result<()>;
}

/// A cheap, cloneable handle to a transport that supports concurrent use.
///
/// See [`SyncStream::shared_handle`]. Cloning is an `Arc` bump, so a relay can
/// hand a copy to each direction and to the cancellation hook without copying
/// the transport.
#[derive(Clone)]
pub struct SharedStream(Arc<dyn StreamHandle>);

impl SharedStream {
    /// Wrap a transport handle.
    pub fn new<H: StreamHandle + 'static>(handle: H) -> Self {
        Self(Arc::new(handle))
    }

    /// Read whatever is available. May block for as long as the peer takes.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read_shared(buf)
    }

    /// Write what the peer will accept; a short write is not an error.
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.0.write_shared(buf)
    }

    /// Release anything blocked on this transport.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.0.shutdown_shared(how)
    }
}

/// Whether a failed half-close really left the half open.
///
/// Half-closing is idempotent by intent but not by API: macOS answers a
/// repeated `shutdown(Write)` with `ENOTCONN` (`NotConnected`) where Linux and
/// Windows return success, and a peer that vanished can surface a reset or a
/// broken pipe instead. In all of those cases the half is already unusable —
/// the state the caller asked for — so a relay teardown must not report them
/// as failures.
pub fn is_benign_shutdown_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotConnected
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
    )
}

/// [`SyncStream::shutdown`] that treats an already-closed half as success.
///
/// Streams that *wrap* a transport (VMess, Shadowsocks, WebSocket, TLS with a
/// socket half-close hook) forward to something that does not necessarily go
/// through [`SyncStream for TcpStream`], so they apply the same tolerance
/// here instead of relying on the socket implementation.
pub fn shutdown_lenient(stream: &dyn SyncStream, how: Shutdown) -> io::Result<()> {
    match stream.shutdown(how) {
        Err(error) if is_benign_shutdown_error(&error) => Ok(()),
        other => other,
    }
}

impl StreamHandle for TcpStream {
    /// `Read` is implemented for `&TcpStream` precisely so a socket can be read
    /// from one thread and written from another without a lock: the two
    /// operations touch the same file description but not the same state.
    fn read_shared(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut socket = self;
        socket.read(buf)
    }

    fn write_shared(&self, buf: &[u8]) -> io::Result<usize> {
        let mut socket = self;
        socket.write(buf)
    }

    fn shutdown_shared(&self, how: Shutdown) -> io::Result<()> {
        match TcpStream::shutdown(self, how) {
            Err(error) if is_benign_shutdown_error(&error) => Ok(()),
            other => other,
        }
    }
}

impl SyncStream for TcpStream {
    /// Best-effort half-close, exactly as the trait promises: a repeated
    /// `shutdown(Write)` is `ENOTCONN` on macOS and a vanished peer can answer
    /// with a reset, but neither leaves the half usable.
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match TcpStream::shutdown(self, how) {
            Err(error) if is_benign_shutdown_error(&error) => Ok(()),
            other => other,
        }
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

    /// A socket qualifies, and the handle is a duplicated descriptor pointing
    /// at the same connection. `SO_RCVTIMEO`/`SO_SNDTIMEO` are properties of
    /// the socket, not of the descriptor, so timeouts set through this handle
    /// or the original still agree.
    fn shared_handle(&self) -> Option<SharedStream> {
        TcpStream::try_clone(self).ok().map(SharedStream::new)
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
                std::thread::sleep(RELAY_POLL_YIELD);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Bidirectionally relay two duplex streams on dedicated threads.
///
/// Two copy threads — one per direction — each doing a blocking copy. When a
/// direction reaches EOF it half-closes the opposite peer; on error or
/// cancellation both transports are shut down so the peer thread wakes and
/// exits promptly.
///
/// The copy threads are dedicated OS threads (not pool workers) so a relay
/// can never starve the work-stealing pool of handshake capacity; the
/// number of concurrent relays is bounded upstream by
/// [`crate::common::exec::SessionGate`].
///
/// # Idle cost
///
/// A relay is idle for most of a connection's life — a browser holds hundreds
/// of keep-alive sockets that are silent almost all the time — so what a
/// silent connection costs dominates the device's power draw. The design goal
/// is therefore that an idle direction is *parked*, not ticking: see
/// [`relay`] for how a transport that supports concurrent use gets there, and
/// [`RELAY_READ_POLL`] for the fallback.
///
/// One end of a relay.
///
/// The distinction is the whole point of the relay's design: a side that can be
/// used concurrently needs no bound on its reads and no lock to hand over,
/// while a side that cannot still has to give the other direction a turn.
enum Side {
    /// The transport exposes a [`SharedStream`], so both directions can read
    /// and write it without coordinating. Reads may park indefinitely: nothing
    /// is held while they wait, and cancellation shuts the transport down.
    Shared(SharedStream),
    /// Read and write go through one object behind one lock, so every
    /// operation has to be bounded by [`RELAY_READ_POLL`].
    Serialized(Arc<Mutex<BoxStream>>),
}

impl Side {
    fn new(stream: BoxStream, shared: Option<SharedStream>) -> Self {
        match shared {
            // The original handle is dropped. The transport stays open because
            // the shared handle is a second descriptor for the same object.
            Some(shared) => Side::Shared(shared),
            None => Side::Serialized(Arc::new(Mutex::new(stream))),
        }
    }

    /// Whether this side took the concurrent path. Test-only: the relay does
    /// not branch on it, it just behaves differently.
    #[cfg(test)]
    fn is_shared(&self) -> bool {
        matches!(self, Side::Shared(_))
    }

    /// Release anything parked on this side, in both directions.
    fn release(&self) {
        self.shutdown(Shutdown::Both);
    }

    fn shutdown(&self, how: Shutdown) {
        match self {
            Side::Shared(shared) => {
                let _ = shared.shutdown(how);
            }
            Side::Serialized(stream) => {
                let guard = lock_stream(stream);
                let _ = shutdown_lenient(&**guard, how);
            }
        }
    }

    /// Read one chunk. `Ok(None)` means "nothing to move yet, and any lock has
    /// been given back" — never "spinning on an empty socket".
    fn read(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        match self {
            Side::Shared(shared) => match shared.read(buf) {
                Ok(n) => Ok(Some(n)),
                Err(e) if is_read_interval_elapsed(&e) => {
                    std::thread::sleep(RELAY_POLL_YIELD);
                    Ok(None)
                }
                Err(e) => Err(e),
            },
            Side::Serialized(stream) => {
                let mut guard = lock_stream(stream);
                match guard.read(buf) {
                    Ok(n) => Ok(Some(n)),
                    Err(e) if is_read_interval_elapsed(&e) => {
                        drop(guard);
                        std::thread::sleep(RELAY_POLL_YIELD);
                        Ok(None)
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }

    fn write_all(&self, data: &[u8]) -> io::Result<()> {
        match self {
            Side::Shared(shared) => {
                let mut written = 0;
                while written < data.len() {
                    match shared.write(&data[written..]) {
                        Ok(0) => {
                            return Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "relay write made no progress",
                            ))
                        }
                        Ok(n) => written += n,
                        Err(e) => return Err(e),
                    }
                }
                Ok(())
            }
            Side::Serialized(stream) => lock_stream(stream).write_all(data),
        }
    }
}

/// `true` when a bounded read reports that its interval elapsed.
///
/// Linux surfaces `SO_RCVTIMEO` as `EAGAIN`, Windows as `WSAETIMEDOUT`, so both
/// kinds have to count as "the clock ran out" for the serialized path to work
/// on every platform.
fn is_read_interval_elapsed(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// Take a serialized side's lock, tolerating poisoning: a panic in one
/// direction must not turn the other direction's teardown into a panic.
fn lock_stream(stream: &Arc<Mutex<BoxStream>>) -> std::sync::MutexGuard<'_, BoxStream> {
    stream.lock().unwrap_or_else(|e| e.into_inner())
}

/// Per-chunk accounting for a relay, for callers that report traffic.
///
/// The callbacks run on the relay's own copy threads, once per chunk, so an
/// implementation has to be cheap and must not block: it is on the data path.
#[derive(Clone, Default)]
pub struct RelayAccounting {
    /// Bytes copied client → upstream.
    pub upstream: Option<Arc<dyn Fn(u64) + Send + Sync>>,
    /// Bytes copied upstream → client.
    pub downstream: Option<Arc<dyn Fn(u64) + Send + Sync>>,
}

impl RelayAccounting {
    fn record(&self, upstream: bool, bytes: u64) {
        let hook = if upstream {
            self.upstream.as_ref()
        } else {
            self.downstream.as_ref()
        };
        if let Some(hook) = hook {
            hook(bytes);
        }
    }
}

/// Copy `src` to `dst` until a side finishes, the relay is cancelled, or a
/// transport fails.
fn copy_direction(
    src: Arc<Side>,
    dst: Arc<Side>,
    token: CancellationToken,
    stats: Arc<Mutex<RelayStats>>,
    accounting: RelayAccounting,
    upstream: bool,
) -> io::Result<()> {
    let mut buf = vec![0u8; RELAY_BUF_SIZE];
    loop {
        if token.is_cancelled() {
            src.release();
            dst.release();
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }

        let n = match src.read(&mut buf) {
            Ok(Some(0)) => {
                if token.is_cancelled() {
                    dst.release();
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
                }
                dst.shutdown(Shutdown::Write);
                return Ok(());
            }
            Ok(Some(n)) => n,
            // Nothing to move yet. `Side::read` has already handed back any
            // serialized lock it took, and this sleep is the loop's own
            // guarantee that it never re-enters a read without having yielded
            // the CPU first — even for a transport that reports "no progress"
            // without ever having blocked. Without it, a handle that returns
            // `WouldBlock` immediately turns this into a userspace spin: no
            // syscalls, no I/O, one saturated core per relay direction.
            Ok(None) => {
                std::thread::sleep(RELAY_POLL_YIELD);
                continue;
            }
            Err(e) => {
                src.release();
                dst.release();
                return Err(e);
            }
        };

        if let Err(e) = dst.write_all(&buf[..n]) {
            src.release();
            dst.release();
            return Err(e);
        }

        {
            let mut stats = stats.lock().unwrap_or_else(|e| e.into_inner());
            if upstream {
                stats.up += n as u64;
            } else {
                stats.down += n as u64;
            }
        }
        accounting.record(upstream, n as u64);
    }
}

/// Copy bytes both ways between two transports until a side finishes or the
/// token is cancelled.
///
/// # Why this is not just a pair of bounded copies
///
/// Sharing one `&mut` stream between the two directions is what forces a bound
/// on every read: a direction parked in `read` would otherwise hold the lock
/// forever and the opposite direction could never write to the same transport.
/// That bound is a poll interval in disguise — it wakes the thread, hands the
/// lock over, and makes the opposite direction's write wait for it — so it sits
/// in the middle of a power/latency trade-off with no good setting: shortening
/// it costs wake-ups, lengthening it costs latency, and neither end is
/// acceptable.
///
/// A transport that offers a [`SharedStream`] removes the premise. Both
/// directions then hold a handle, no lock is held across a read, and reads are
/// left unbounded — so an idle connection costs nothing, a parked read is woken
/// by the data itself, and cancellation arrives through
/// [`CancellationToken::on_cancel`] shutting the transport down instead of
/// through a timer. The serialized path is kept for transports whose read and
/// write genuinely share mutable state (a TLS or AEAD record layer), where
/// serializing is correct and the interval is only as short as it must be.
///
/// The two are not exclusive: a relay between a plain socket and a wrapped
/// transport gets the lock-free direction on the socket side as well.
/// [`relay`] with per-chunk accounting.
pub fn relay_with(
    a: BoxStream,
    b: BoxStream,
    token: CancellationToken,
    accounting: RelayAccounting,
) -> io::Result<RelayStats> {
    let a_shared = a.shared_handle();
    let b_shared = b.shared_handle();

    if a_shared.is_some() {
        let _ = a.set_read_timeout(None);
    } else {
        let _ = a.set_read_timeout(Some(RELAY_READ_POLL));
    }
    if b_shared.is_some() {
        let _ = b.set_read_timeout(None);
    } else {
        let _ = b.set_read_timeout(Some(RELAY_READ_POLL));
    }
    let _ = a.set_write_timeout(Some(RELAY_WRITE_TIMEOUT));
    let _ = b.set_write_timeout(Some(RELAY_WRITE_TIMEOUT));

    let a = Arc::new(Side::new(a, a_shared));
    let b = Arc::new(Side::new(b, b_shared));

    if token.is_cancelled() {
        a.release();
        b.release();
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "relay cancelled",
        ));
    }

    {
        let a = Arc::clone(&a);
        let b = Arc::clone(&b);
        token.on_cancel(move || {
            a.release();
            b.release();
        });
    }

    let stats = Arc::new(Mutex::new(RelayStats::default()));

    let upstream = {
        let src = Arc::clone(&a);
        let dst = Arc::clone(&b);
        let token = token.clone();
        let stats = Arc::clone(&stats);
        let accounting = accounting.clone();
        std::thread::Builder::new()
            .name("corduit-relay-up".into())
            .spawn(move || copy_direction(src, dst, token, stats, accounting, true))
    };

    // Both spawns and both joins have to complete on every path out of this
    // function. A `?` between the two spawns used to return while the first
    // thread was already running: nothing owned it any more, so it kept its
    // two streams, its buffers and its spot in the thread table for the life
    // of the process. On a device that opens a connection per app flow the
    // strays accumulate until thread creation itself starts failing, which is
    // what turned a leak into a storm.
    let upstream = match upstream {
        Ok(handle) => handle,
        Err(error) => {
            a.release();
            b.release();
            return Err(error);
        }
    };

    let downstream = {
        let src = Arc::clone(&b);
        let dst = Arc::clone(&a);
        let token = token.clone();
        let stats = Arc::clone(&stats);
        let accounting = accounting.clone();
        std::thread::Builder::new()
            .name("corduit-relay-down".into())
            .spawn(move || copy_direction(src, dst, token, stats, accounting, false))
    };

    let downstream = match downstream {
        Ok(handle) => handle,
        Err(error) => {
            // The upstream thread is already running and holds both sides.
            // Releasing them is what wakes it, and joining it is what keeps
            // this function the sole owner of every thread it started.
            a.release();
            b.release();
            let _ = upstream.join();
            return Err(error);
        }
    };

    // Both joins run before any `?`, so a panic in one direction can never
    // return early and strand the other thread.
    let up = upstream.join();

    // A panicking direction unwinds without releasing anything, so the other
    // one can still be parked in a read that will never see data again.
    // Release both sides before waiting for it, or this join never returns.
    if up.is_err() {
        a.release();
        b.release();
    }

    let down = downstream.join();

    let up = up.map_err(|_| io::Error::other("relay thread panicked"))?;
    let down = down.map_err(|_| io::Error::other("relay thread panicked"))?;

    if token.is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "relay cancelled",
        ));
    }
    up.and(down)?;

    let stats = Arc::try_unwrap(stats)
        .map(|m| m.into_inner().unwrap_or_default())
        .unwrap_or_default();
    Ok(stats)
}

/// Copy bytes both ways between two transports, reporting nothing.
///
/// Shorthand for [`relay_with`] with the default accounting.
pub fn relay(a: BoxStream, b: BoxStream, token: CancellationToken) -> io::Result<RelayStats> {
    relay_with(a, b, token, RelayAccounting::default())
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

    /// Only errors that mean "this half is already closed" are tolerated:
    /// a genuine failure still has to reach the caller.
    #[test]
    fn benign_shutdown_errors_are_the_already_closed_ones() {
        for kind in [
            io::ErrorKind::NotConnected,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
        ] {
            assert!(
                is_benign_shutdown_error(&io::Error::new(kind, "closed")),
                "{kind:?} means the half is already closed"
            );
        }
        for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::InvalidInput] {
            assert!(
                !is_benign_shutdown_error(&io::Error::new(kind, "real failure")),
                "{kind:?} must reach the caller"
            );
        }
    }

    /// A second `shutdown(Write)` must stay `Ok` (macOS: `ENOTCONN`) —
    /// including after the peer is gone, which is the state a relay teardown
    /// half-closes in.
    #[test]
    fn tcp_half_close_is_idempotent() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        drop(server);

        assert!(SyncStream::shutdown(&client, Shutdown::Write).is_ok());
        assert!(SyncStream::shutdown(&client, Shutdown::Write).is_ok());
        assert!(SyncStream::shutdown(&client, Shutdown::Both).is_ok());
    }

    /// A connected pair of loopback sockets, as a client/proxy or proxy/server
    /// pair looks to a relay.
    fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let connector = std::thread::spawn(move || TcpStream::connect(addr).expect("connect"));
        let (accepted, _peer) = listener.accept().expect("accept");
        let connected = connector.join().expect("connect thread");
        (accepted, connected)
    }

    /// A plain socket must advertise the concurrent path, because that is what
    /// decides whether a relay polls or parks.
    #[test]
    fn a_socket_offers_a_shared_handle() {
        let (socket, _peer) = socket_pair();
        let handle = socket.shared_handle().expect("a socket is concurrent");
        let side = Side::new(Box::new(socket), Some(handle));
        assert!(side.is_shared());
    }

    /// Bytes must cross a socket relay in both directions, and — the point of
    /// the change — the direction back towards the client must not wait for a
    /// poll interval, because no lock stands between it and the socket.
    #[test]
    fn socket_relay_moves_data_both_ways() {
        let (proxy_client_side, client_peer) = socket_pair();
        let (proxy_server_side, server_peer) = socket_pair();

        client_peer
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("client timeout");
        server_peer
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("server timeout");

        let token = CancellationToken::new();
        let relay_token = token.clone();
        let relayed = std::thread::spawn(move || {
            relay(
                Box::new(proxy_client_side),
                Box::new(proxy_server_side),
                relay_token,
            )
        });

        let mut client_reader = &client_peer;
        let mut server_reader = &server_peer;
        let mut client_writer = &client_peer;
        let mut server_writer = &server_peer;

        client_writer.write_all(b"ping").expect("write up");
        let mut buf = [0u8; 4];
        server_reader.read_exact(&mut buf).expect("read up");
        assert_eq!(&buf, b"ping");

        server_writer.write_all(b"pong").expect("write down");
        let mut buf = [0u8; 4];
        client_reader.read_exact(&mut buf).expect("read down");
        assert_eq!(&buf, b"pong");

        let _ = client_peer.shutdown(Shutdown::Both);
        let _ = server_peer.shutdown(Shutdown::Both);

        let stats = relayed
            .join()
            .expect("relay thread")
            .expect("a clean close is not a relay failure");
        assert_eq!(stats.up, 4, "upstream bytes");
        assert_eq!(stats.down, 4, "downstream bytes");
    }

    /// Cancelling has to release both directions: a concurrent side reads with
    /// no timeout, so a shutdown from the hook is the only thing that can end
    /// a parked read. This test hangs rather than fails if that regresses.
    #[test]
    fn cancel_releases_a_socket_relay() {
        let (proxy_client_side, _client_peer) = socket_pair();
        let (proxy_server_side, _server_peer) = socket_pair();

        let token = CancellationToken::new();
        let relay_token = token.clone();
        let relayed = std::thread::spawn(move || {
            relay(
                Box::new(proxy_client_side),
                Box::new(proxy_server_side),
                relay_token,
            )
        });

        std::thread::sleep(Duration::from_millis(50));
        token.cancel();

        let outcome = relayed.join().expect("relay thread");
        assert!(outcome.is_err(), "a cancelled relay reports interruption");
    }

    /// A transport that has nothing to hand over until it is released, and that
    /// reports when it is finally dropped.
    ///
    /// `WouldBlock` rather than a parked syscall keeps the copy thread inside
    /// the relay's own loop, so the thread is alive for exactly as long as the
    /// relay owns it — which is the property under test. The drop flag is the
    /// only cross-platform way to tell a joined thread from a stray one: a
    /// thread that outlives `relay` still holds its `Arc<Side>`, and therefore
    /// still holds the transport.
    struct Parking {
        released: std::sync::Arc<std::sync::atomic::AtomicBool>,
        dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
        panic_on_read: bool,
    }

    impl Read for Parking {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            assert!(
                !self.panic_on_read,
                "the upstream direction was told to panic"
            );
            if self.released.load(std::sync::atomic::Ordering::SeqCst) {
                return Ok(0);
            }
            Err(io::Error::new(io::ErrorKind::WouldBlock, "nothing yet"))
        }
    }

    impl Write for Parking {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl SyncStream for Parking {
        fn shutdown(&self, _how: Shutdown) -> io::Result<()> {
            self.released
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    impl Drop for Parking {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// A direction that unwinds must not leave its partner parked.
    ///
    /// This is the leak that turned into a storm on device: `relay_with`
    /// returned on the panicking join without joining the other thread, so that
    /// thread kept both transports (and their sockets) for the life of the
    /// process, and a failing spawn did the same to a thread that had not even
    /// started working yet. Both transports being dropped is the proof that no
    /// thread is still holding them.
    #[test]
    fn a_panicking_direction_does_not_strand_its_partner() {
        let up_released = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let up_dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let down_released = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let down_dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let upstream: BoxStream = Box::new(Parking {
            released: std::sync::Arc::clone(&up_released),
            dropped: std::sync::Arc::clone(&up_dropped),
            panic_on_read: true,
        });
        let downstream: BoxStream = Box::new(Parking {
            released: std::sync::Arc::clone(&down_released),
            dropped: std::sync::Arc::clone(&down_dropped),
            panic_on_read: false,
        });

        let outcome = relay(upstream, downstream, CancellationToken::new());

        assert!(
            outcome.is_err(),
            "a panicking direction has to fail the relay"
        );
        assert!(
            down_released.load(std::sync::atomic::Ordering::SeqCst),
            "the surviving direction was left parked instead of released"
        );
        assert!(
            up_dropped.load(std::sync::atomic::Ordering::SeqCst),
            "the upstream transport is still owned by a live thread"
        );
        assert!(
            down_dropped.load(std::sync::atomic::Ordering::SeqCst),
            "the downstream transport is still owned by a live thread"
        );
    }

    /// A relay that never sees data must poll, not spin: the no-progress path
    /// has to sleep, so a silent connection costs a wake-up per poll interval
    /// rather than a saturated core.
    #[test]
    fn a_silent_relay_parks_between_polls() {
        let upstream: BoxStream = Box::new(Parking {
            released: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            dropped: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            panic_on_read: false,
        });
        let downstream: BoxStream = Box::new(Parking {
            released: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            dropped: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            panic_on_read: false,
        });

        let token = CancellationToken::new();
        let relay_token = token.clone();
        let relayed = std::thread::spawn(move || relay(upstream, downstream, relay_token));
        let start = std::time::Instant::now();
        let before = cpu_time();
        std::thread::sleep(Duration::from_millis(300));
        let burned = cpu_time().saturating_sub(before);
        let elapsed = start.elapsed();

        token.cancel();
        let _ = relayed.join().expect("relay thread");

        assert!(
            burned < 150_000,
            "a silent relay burned {burned:?} of CPU in {elapsed:?}"
        );
    }

    /// This process's own CPU time, in microseconds.
    #[cfg(target_os = "linux")]
    fn cpu_time() -> u64 {
        let stat = std::fs::read_to_string("/proc/self/stat").expect("own stat");
        let rest = stat.split_once(") ").expect("comm").1;
        let fields: Vec<&str> = rest.split_whitespace().collect();
        let utime: u64 = fields[11].parse().expect("utime");
        let stime: u64 = fields[12].parse().expect("stime");
        // 100 ticks per second on every Linux kernel this runs on.
        (utime + stime) * 10_000
    }

    #[cfg(not(target_os = "linux"))]
    fn cpu_time() -> u64 {
        std::thread::sleep(Duration::from_millis(1));
        0
    }
}
