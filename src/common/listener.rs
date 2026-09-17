//! A bounded listener that runs one blocking server engine per connection.
//!
//! Corduit's servers own their accept loops because two of them need
//! something the bundled scheduler does not provide:
//!
//! * the `http` / `mixed` inbounds hand a `CONNECT` connection to a relay
//!   that blocks for the tunnel's lifetime;
//! * the `mixed` inbound must sniff the first byte of every connection
//!   before deciding which protocol it speaks.
//!
//! [`courierust_server::serve_connection`] is the public entry point for
//! exactly that situation — the full per-connection engine (TLS/ALPN,
//! HTTP/1.1 and HTTP/2, keep-alive, `CONNECT` tunnels, WebSocket upgrades)
//! over a socket the caller accepted. This listener supplies the accept
//! loop and the concurrency bound around it: one dedicated thread per
//! connection, with the accept thread applying backpressure once
//! `max_sessions` connections are live.
//!
//! # The accept loop does not poll
//!
//! A listener sits idle for almost all of its life, so the cost of accepting
//! nothing has to be zero. The obvious implementation — a non-blocking
//! listener plus a short sleep on `WouldBlock` — spends a wake-up on every idle
//! tick forever (a 10 ms tick is a hundred a second, per listener, whether or
//! not anyone connects), keeps the CPU out of its deep idle states, and
//! *still* delays a connection that arrives just after a tick by the rest of
//! the interval.
//!
//! This loop instead blocks in `accept` and is released by
//! [`CancellationToken::on_cancel`]: stopping the listener connects to its own
//! address, the kernel wakes the blocked `accept`, the loop sees the flag and
//! leaves. Idle cost is zero and the stop is immediate, both because the event
//! that ends the wait is the event that asked for it.
//!
//! [`courierust_server::serve_connection`]: courierust::courierust_server::serve_connection

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::common::cancel::CancellationToken;

/// Budget for the single connect that releases a blocked `accept`.
///
/// Loopback handshakes complete in microseconds; the budget only exists so a
/// listener that has already closed cannot stall the stop path.
const WAKE_CONNECT_TIMEOUT: Duration = Duration::from_millis(100);

/// Pause after an `accept` that failed transiently in a way the loop cannot
/// interpret. Unreachable on a blocking listener, and deliberately paced so a
/// listener that somehow ends up non-blocking backs off instead of spinning.
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(5);

/// A shared admission counter for live connections.
struct Slots {
    max: usize,
    active: AtomicUsize,
    wake: (Mutex<()>, Condvar),
}

/// A permit for one live connection; releases its slot on drop.
struct Slot(Arc<Slots>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.release();
    }
}

impl Slots {
    fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            max: max.max(1),
            active: AtomicUsize::new(0),
            wake: (Mutex::new(()), Condvar::new()),
        })
    }

    /// Wait for a free slot and take it.
    ///
    /// Returns `None` when the listener is cancelled while waiting: without
    /// that check a stop request against a listener at its concurrency limit
    /// would block the accept thread (and the `stop`/`drop` join) until a
    /// live connection happened to finish.
    ///
    /// The wait carries no timeout. It is released by [`Slots::release`] the
    /// moment a slot frees, and by the listener's cancel hook, so the only
    /// thing a tick could add is wake-ups.
    fn acquire(slots: &Arc<Self>, cancel: &CancellationToken) -> Option<Slot> {
        let (lock, cond) = &slots.wake;
        let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        while !cancel.is_cancelled() && slots.active.load(Ordering::Acquire) >= slots.max {
            guard = cond.wait(guard).unwrap_or_else(|e| e.into_inner());
        }
        if cancel.is_cancelled() {
            return None;
        }
        slots.active.fetch_add(1, Ordering::AcqRel);
        Some(Slot(Arc::clone(slots)))
    }

    fn release(&self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
        let (lock, cond) = &self.wake;
        let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        cond.notify_one();
    }

    /// Release every waiter. Used by the cancel hook: a worker parked in
    /// [`Slots::acquire`] is not in `accept`, so the wake-up connection cannot
    /// reach it.
    fn wake_all(&self) {
        let (lock, cond) = &self.wake;
        let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        cond.notify_all();
    }
}

/// A listener serving connections on dedicated threads, with graceful stop.
pub struct ConnectionListener {
    addr: SocketAddr,
    listener: Option<TcpListener>,
    cancel: CancellationToken,
    running: Arc<AtomicBool>,
    accept_thread: Option<JoinHandle<()>>,
    slots: Arc<Slots>,
}

impl ConnectionListener {
    /// Wrap a bound listener.
    ///
    /// `max_sessions` bounds how many connections may be served at once; the
    /// accept loop blocks until a slot frees, so the surplus waits in the
    /// kernel's backlog instead of spawning unbounded threads.
    ///
    /// A caller may hand over a listener in any mode — [`start`](Self::start)
    /// switches it to blocking, because the accept loop parks in `accept` and
    /// is released by cancellation rather than by a tick.
    pub fn new(listener: TcpListener, addr: SocketAddr, max_sessions: usize) -> Self {
        Self {
            addr,
            listener: Some(listener),
            cancel: CancellationToken::new(),
            running: Arc::new(AtomicBool::new(false)),
            accept_thread: None,
            slots: Slots::new(max_sessions),
        }
    }

    /// The bound address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Whether the accept loop is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Connections currently being served.
    pub fn active(&self) -> usize {
        self.slots.active.load(Ordering::Acquire)
    }

    /// Start accepting. `handler` runs on a thread of its own per connection;
    /// `thread_name` labels those threads.
    pub fn start<F>(&mut self, thread_name: &'static str, handler: F) -> io::Result<()>
    where
        F: Fn(TcpStream, SocketAddr) + Send + Sync + 'static,
    {
        if self.accept_thread.is_some() {
            return Ok(());
        }
        let listener = self
            .listener
            .take()
            .ok_or_else(|| io::Error::other("listener already consumed"))?;

        listener.set_nonblocking(false)?;

        let cancel = self.cancel.clone();
        let running = Arc::clone(&self.running);
        let slots = Arc::clone(&self.slots);
        let handler = Arc::new(handler);
        let addr = self.addr;

        let wake_address = wake_target(addr);
        let waking_slots = Arc::clone(&self.slots);
        cancel.on_cancel(move || {
            wake_accept(&wake_address);
            waking_slots.wake_all();
        });

        running.store(true, Ordering::SeqCst);
        self.accept_thread = Some(
            std::thread::Builder::new()
                .name(thread_name.into())
                .spawn(move || {
                    loop {
                        if cancel.is_cancelled() {
                            break;
                        }
                        match listener.accept() {
                            Ok((stream, peer)) => {
                                if cancel.is_cancelled() {
                                    drop(stream);
                                    break;
                                }
                                if let Err(error) = stream.set_nonblocking(false) {
                                    tracing::warn!("accepted socket keeps its mode: {error}");
                                }
                                let Some(slot) = Slots::acquire(&slots, &cancel) else {
                                    drop(stream);
                                    break;
                                };
                                let handler = Arc::clone(&handler);
                                let worker = std::thread::Builder::new()
                                    .name(thread_name.into())
                                    .spawn(move || {
                                        let _slot = slot;
                                        handler(stream, peer);
                                    });
                                if worker.is_err() {
                                    tracing::error!("failed to spawn a connection thread");
                                }
                            }
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    io::ErrorKind::ConnectionAborted
                                        | io::ErrorKind::ConnectionReset
                                        | io::ErrorKind::Interrupted
                                ) =>
                            {
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                std::thread::sleep(ACCEPT_ERROR_PAUSE);
                            }
                            Err(e) => {
                                if !cancel.is_cancelled() {
                                    tracing::error!("accept error on {}: {}", addr, e);
                                }
                                break;
                            }
                        }
                    }
                    running.store(false, Ordering::SeqCst);
                })
                .map_err(|e| io::Error::other(format!("failed to spawn accept thread: {e}")))?,
        );
        Ok(())
    }

    /// Stop accepting and wait for the accept loop to exit. Connections
    /// already running keep their threads until they finish.
    pub fn stop(&mut self) {
        self.cancel.cancel();
        if let Some(thread) = self.accept_thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for ConnectionListener {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The address a wake-up connection should be aimed at.
///
/// A listener bound to a wildcard address does not answer at the wildcard
/// address, so the wake-up goes to the loopback of the same family instead.
fn wake_target(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), addr.port())
        }
        _ => addr,
    }
}

/// Release a worker parked in a blocking `accept` by connecting to the
/// listener it owns. The connection is accepted and dropped; its only job is
/// to make `accept` return so the loop can read the cancellation flag.
///
/// One attempt with a short budget is deliberate. Once the accept thread has
/// already left, the port is closed — and a closed loopback port is not
/// refused on every platform, it can sit until the connect budget expires.
/// Paying that once, bounded, is better than retrying into a longer stall on
/// the stop path, and it cannot lose the wake-up in the case that matters:
/// while the thread *is* parked in `accept`, the handshake completes in
/// microseconds.
fn wake_accept(target: &SocketAddr) {
    let Ok(stream) = TcpStream::connect_timeout(target, WAKE_CONNECT_TIMEOUT) else {
        return;
    };
    let _ = stream.shutdown(Shutdown::Both);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// The whole point of the blocking design: an idle listener must cost
    /// nothing, and stopping it must still be immediate. This test would hang
    /// rather than fail if the wake-up stopped working.
    #[test]
    fn stop_is_immediate_while_idle() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut listener = ConnectionListener::new(listener, addr, 8);

        let served = Arc::new(AtomicUsize::new(0));
        let counter = served.clone();
        listener
            .start("test-accept", move |_stream, _peer| {
                counter.fetch_add(1, Ordering::AcqRel);
            })
            .expect("start");

        assert!(listener.is_running());

        let began = std::time::Instant::now();
        listener.stop();
        let elapsed = began.elapsed();

        assert!(
            !listener.is_running(),
            "the accept thread must have left the loop"
        );
        assert_eq!(served.load(Ordering::Acquire), 0, "nothing connected");
        assert!(
            elapsed < Duration::from_millis(500),
            "an idle listener took {elapsed:?} to stop; it must not wait out a poll interval"
        );
    }

    /// A real connection must still be accepted, and accepted promptly: the
    /// blocking loop has no tick to wait for.
    #[test]
    fn accepts_a_connection_after_starting() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut listener = ConnectionListener::new(listener, addr, 8);

        let (tx, rx) = std::sync::mpsc::channel();
        listener
            .start("test-accept", move |_stream, peer| {
                let _ = tx.send(peer);
            })
            .expect("start");

        let client = TcpStream::connect(addr).expect("connect");
        let peer = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the listener should hand the connection to a worker");
        assert_eq!(peer.port(), client.local_addr().expect("client addr").port());

        listener.stop();
    }

    /// Stopping a listener that was never started must not hang or panic: the
    /// hook has nothing to wake, and `stop` still has to be safe.
    #[test]
    fn stop_without_start_is_a_noop() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut listener = ConnectionListener::new(listener, addr, 2);
        listener.stop();
        listener.stop();
    }

    #[test]
    fn wildcard_addresses_are_woken_on_loopback() {
        let v4: SocketAddr = "0.0.0.0:8080".parse().expect("addr");
        assert_eq!(
            wake_target(v4),
            "127.0.0.1:8080".parse::<SocketAddr>().expect("addr")
        );
        let v6: SocketAddr = "[::]:8080".parse().expect("addr");
        assert_eq!(
            wake_target(v6),
            "[::1]:8080".parse::<SocketAddr>().expect("addr")
        );
        let specific: SocketAddr = "10.0.0.5:8080".parse().expect("addr");
        assert_eq!(wake_target(specific), specific);
    }

    /// The slot gate releases waiters through a condvar that now has no
    /// timeout, so cancellation has to notify it explicitly.
    #[test]
    fn cancel_releases_a_thread_waiting_for_a_slot() {
        let slots = Slots::new(1);
        let cancel = CancellationToken::new();
        let held = Slots::acquire(&slots, &cancel).expect("first slot");

        let waiter_cancel = cancel.clone();
        let waiter_slots = Arc::clone(&slots);
        let waiter = std::thread::spawn(move || {
            Slots::acquire(&waiter_slots, &waiter_cancel).is_none()
        });

        std::thread::sleep(Duration::from_millis(20));
        cancel.on_cancel({
            let slots = Arc::clone(&slots);
            move || slots.wake_all()
        });
        cancel.cancel();

        assert!(
            waiter.join().expect("waiter thread"),
            "a cancelled listener must not leave a thread waiting for a slot"
        );
        drop(held);
    }
}
