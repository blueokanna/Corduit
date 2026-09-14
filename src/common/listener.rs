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
//! [`courierust_server::serve_connection`]: courierust::courierust_server::serve_connection

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::common::cancel::CancellationToken;

/// Accept-loop poll interval while the listener is idle.
const ACCEPT_POLL: Duration = Duration::from_millis(10);

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
    fn acquire(slots: &Arc<Self>, cancel: &CancellationToken) -> Option<Slot> {
        let (lock, cond) = &slots.wake;
        let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        while !cancel.is_cancelled() && slots.active.load(Ordering::Acquire) >= slots.max {
            let (g, _timeout) = cond
                .wait_timeout(guard, ACCEPT_POLL)
                .unwrap_or_else(|e| e.into_inner());
            guard = g;
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
    /// Wrap a bound (non-blocking) listener.
    ///
    /// `max_sessions` bounds how many connections may be served at once; the
    /// accept loop blocks until a slot frees, so the surplus waits in the
    /// kernel's backlog instead of spawning unbounded threads.
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

        let cancel = self.cancel.clone();
        let running = Arc::clone(&self.running);
        let slots = Arc::clone(&self.slots);
        let handler = Arc::new(handler);
        let addr = self.addr;

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
                                let Some(slot) = Slots::acquire(&slots, &cancel) else {
                                    drop(stream);
                                    break;
                                };
                                let handler = Arc::clone(&handler);
                                let worker = std::thread::Builder::new()
                                    .name(thread_name.into())
                                    .spawn(move || {
                                        let _slot = slot;
                                        let _ = stream.set_nonblocking(false);
                                        handler(stream, peer);
                                    });
                                if worker.is_err() {
                                    tracing::error!("failed to spawn a connection thread");
                                }
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                std::thread::sleep(ACCEPT_POLL);
                            }
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    io::ErrorKind::ConnectionAborted
                                        | io::ErrorKind::ConnectionReset
                                        | io::ErrorKind::Interrupted
                                ) =>
                            {
                                // A peer that disappeared between the SYN and
                                // the accept (Windows reports `WSAECONNRESET`
                                // this way) or an EINTR: the listener itself
                                // is still healthy.
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
