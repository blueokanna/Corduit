//! The synchronous TLS stream: wraps courierust's blocking
//! [`TlsStream`](courierust::courierust_tls::TlsStream) and presents the
//! engine's [`SyncStream`](crate::common::stream::SyncStream) surface
//! (`std::io::Read` / `std::io::Write` + half-close).
//!
//! The inner courierust stream is guarded by a mutex (mirroring courierust's
//! own `ConnStream`), so the relay's two copy threads can share one TLS
//! stream: the up-thread writes while the down-thread reads. `close_notify`
//! is emitted on write-shutdown, and a full shutdown force-wakes a blocked
//! reader by shutting down the raw socket underneath.

use courierust::courierust_error::ErrorKind as CourierKind;
use courierust::courierust_io::{Read as CRead, Write as CWrite};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A synchronous TLS 1.2 / 1.3 stream over a shared TCP socket.
pub struct TlsStream {
    inner: std::sync::Mutex<courierust::courierust_tls::TlsStream<Arc<TcpStream>, Arc<TcpStream>>>,
    /// The raw socket (used to force-wake a blocked reader on shutdown).
    socket: Arc<TcpStream>,
    peer: Option<SocketAddr>,
    /// `close_notify` has been emitted (write half closed).
    write_closed: AtomicBool,
}

impl TlsStream {
    /// Wrap a completed TLS stream (client or server side).
    pub(crate) fn new(
        tls: courierust::courierust_tls::TlsStream<Arc<TcpStream>, Arc<TcpStream>>,
        socket: Arc<TcpStream>,
    ) -> Self {
        let peer = socket.peer_addr().ok();
        Self {
            inner: std::sync::Mutex::new(tls),
            socket,
            peer,
            write_closed: AtomicBool::new(false),
        }
    }

    /// The negotiated ALPN protocol, if any (copied out of the lock).
    pub fn alpn(&self) -> Option<Vec<u8>> {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.alpn().map(|a| a.to_vec()))
    }

    /// The negotiated TLS version.
    pub fn version(&self) -> courierust::courierust_tls::TlsVersion {
        self.inner
            .lock()
            .map(|g| g.version())
            .unwrap_or(courierust::courierust_tls::TlsVersion::Tls13)
    }

    /// Send a TLS `close_notify` alert (graceful write shutdown). Idempotent.
    pub fn close_notify(&self) {
        if !self.write_closed.swap(true, Ordering::AcqRel) {
            if let Ok(mut guard) = self.inner.try_lock() {
                let _ = guard.close_notify();
                let _ = CWrite::flush(&mut *guard);
            }
        }
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("tls stream lock poisoned"))?;
        match CRead::read(&mut *guard, buf) {
            Ok(n) => Ok(n),
            // A mid-record read timeout is transient — the record layer
            // resumes from the exact byte (documented courierust behavior).
            Err(e) if matches!(e.kind, CourierKind::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "tls read timed out",
            )),
            Err(e) if matches!(e.kind, CourierKind::WouldBlock) => {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "tls would block"))
            }
            Err(e) if matches!(e.kind, CourierKind::UnexpectedEof) => Ok(0),
            Err(e) => Err(io::Error::other(format!("tls read failed: {e}"))),
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("tls stream lock poisoned"))?;
        // courierust's TlsStream::write writes the whole buffer.
        match CWrite::write(&mut *guard, buf) {
            Ok(n) => Ok(n),
            Err(e) => Err(io::Error::other(format!("tls write failed: {e}"))),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("tls stream lock poisoned"))?;
        CWrite::flush(&mut *guard).map_err(|e| io::Error::other(format!("tls flush failed: {e}")))
    }
}

impl crate::common::stream::SyncStream for TlsStream {
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match how {
            Shutdown::Write | Shutdown::Both => self.close_notify(),
            Shutdown::Read => {}
        }
        if how == Shutdown::Both {
            // Force-wake any thread blocked in read() on the raw socket.
            let _ = self.socket.shutdown(Shutdown::Both);
        }
        Ok(())
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer
    }

    fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        self.socket.set_write_timeout(timeout)
    }
}
