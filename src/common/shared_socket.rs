//! A clonable `TcpStream` handle for streams that must own their socket.
//!
//! The engine's relay contract ([`SyncStream`](crate::common::stream::SyncStream))
//! requires `Read`, `Write` **and** `shutdown`. The in-repo TLS 1.3 stream
//! needs two owned handles on one socket (reader + writer) plus a way to shut
//! the socket down from `&self`, which neither `TcpStream` (not `Clone`) nor
//! `Arc<TcpStream>` (no `std::io::Read`/`Write`) provides on its own. This
//! wrapper supplies exactly that.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::time::Duration;

/// A shareable `TcpStream`: cheap to clone, readable, writable and
/// shuttable, so a TLS stream can own both directions while the caller keeps a
/// handle for timeouts and half-close.
#[derive(Clone)]
pub struct SharedTcpStream(Arc<TcpStream>);

impl SharedTcpStream {
    /// Wrap an owned stream.
    pub fn new(stream: TcpStream) -> Self {
        Self(Arc::new(stream))
    }

    /// Set `TCP_NODELAY`.
    pub fn set_nodelay(&self, enabled: bool) -> std::io::Result<()> {
        self.0.set_nodelay(enabled)
    }

    /// Set the socket-wide read timeout (applies to every handle, including
    /// the ones a TLS stream already owns).
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.0.set_read_timeout(timeout)
    }

    /// Set the socket-wide write timeout.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.0.set_write_timeout(timeout)
    }

    /// Shut the socket down (`Shutdown::Write` is the half-close the relay
    /// uses).
    pub fn shutdown(&self, how: Shutdown) -> std::io::Result<()> {
        self.0.shutdown(how)
    }
}

impl Read for SharedTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        (&*self.0).read(buf)
    }
}

impl Write for SharedTcpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (&*self.0).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        (&*self.0).flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// Two handles on one socket carry data in both directions, and shutting
    /// one down is visible to the peer — the properties the relay depends on.
    #[test]
    fn shared_handles_carry_data_and_shutdown() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accept = std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4];
            peer.read_exact(&mut buf).expect("peer read");
            peer.write_all(b"pong").expect("peer write");
            let mut tail = [0u8; 1];
            let n = peer.read(&mut tail).expect("peer read after shutdown");
            (buf, n)
        });

        let stream = SharedTcpStream::new(TcpStream::connect(addr).expect("connect"));
        let mut reader = stream.clone();
        let mut writer = stream.clone();
        writer.write_all(b"ping").expect("write");
        writer.flush().expect("flush");
        let mut echo = [0u8; 4];
        reader.read_exact(&mut echo).expect("read");
        assert_eq!(&echo, b"pong");
        stream.shutdown(Shutdown::Write).expect("half close");

        let (received, tail) = accept.join().expect("thread");
        assert_eq!(&received, b"ping");
        assert_eq!(tail, 0, "peer sees the half-close");
    }
}
