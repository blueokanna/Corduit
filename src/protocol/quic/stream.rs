//! QUIC stream handles (`std::io::Read` / `std::io::Write`) over a shared
//! [`QuicConn`].
//!
//! Reads and writes are synchronous and backpressured: when the send buffer
//! is full or no receive data is available, the call parks on the stream's
//! [`Notify`](crate::common::sync::Notify) for a short poll and re-checks
//! the connection state — the transport's driver thread performs the actual
//! socket IO.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use super::error::QuicError;
use super::transport::{QuicConn, RecvOutcome};

/// How long a stream parks between wakeups before re-checking connection
/// state. Bounded so a connection close is noticed promptly even if a
/// wakeup notification was consumed by another waiter.
const STREAM_POLL: Duration = Duration::from_millis(50);

/// The send half of a QUIC stream.
pub struct QuicSendStream {
    conn: Arc<QuicConn>,
    stream_id: u64,
}

impl QuicSendStream {
    pub(crate) fn new(conn: Arc<QuicConn>, stream_id: u64) -> Self {
        Self { conn, stream_id }
    }

    /// The QUIC stream id.
    pub fn id(&self) -> u64 {
        self.stream_id
    }

    /// Queue the FIN for this stream (the write half closes after all
    /// buffered data is acknowledged).
    pub fn finish(&mut self) -> io::Result<()> {
        let mut st = self.conn.lock();
        if let Some(e) = &st.closed {
            return Err(Self::io_err(e));
        }
        self.conn
            .fin_stream(&mut st, self.stream_id)
            .map_err(|e| Self::io_err(&e))?;
        self.conn.writer.notify_one();
        Ok(())
    }

    fn io_err(e: &QuicError) -> io::Error {
        io::Error::other(e.to_string())
    }
}

impl io::Write for QuicSendStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut st = self.conn.lock();
            if let Some(e) = &st.closed {
                return Err(Self::io_err(e));
            }
            match self.conn.send_data(&mut st, self.stream_id, buf) {
                Ok(n) => {
                    // Wake the driver so the new data hits the wire.
                    self.conn.writer.notify_one();
                    return Ok(n);
                }
                Err(QuicError::StreamLimit) => {
                    // Send buffer full: wait for ACKs / flow control.
                    let notify = self.conn.stream_send_notify(&st, self.stream_id);
                    drop(st);
                    notify.wait(STREAM_POLL);
                }
                Err(e) => return Err(Self::io_err(&e)),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        loop {
            let st = self.conn.lock();
            if let Some(e) = &st.closed {
                return Err(Self::io_err(e));
            }
            if self.conn.send_buffered(&st, self.stream_id) == 0 {
                return Ok(());
            }
            let notify = self.conn.stream_send_notify(&st, self.stream_id);
            drop(st);
            self.conn.writer.notify_one();
            notify.wait(STREAM_POLL);
        }
    }
}

/// The receive half of a QUIC stream.
pub struct QuicRecvStream {
    conn: Arc<QuicConn>,
    stream_id: u64,
}

impl QuicRecvStream {
    pub(crate) fn new(conn: Arc<QuicConn>, stream_id: u64) -> Self {
        Self { conn, stream_id }
    }

    /// The QUIC stream id.
    pub fn id(&self) -> u64 {
        self.stream_id
    }

    fn io_err(e: &QuicError) -> io::Error {
        io::Error::other(e.to_string())
    }
}

impl io::Read for QuicRecvStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut st = self.conn.lock();
            if let Some(e) = &st.closed {
                return Err(Self::io_err(e));
            }
            match self.conn.recv_into(&mut st, self.stream_id, buf) {
                RecvOutcome::Data(n) => return Ok(n),
                RecvOutcome::Eof => return Ok(0),
                RecvOutcome::Reset(code) => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        format!("QUIC stream reset by peer (code {code})"),
                    ))
                }
                RecvOutcome::WouldBlock => {
                    let notify = self.conn.stream_recv_notify(&st, self.stream_id);
                    drop(st);
                    notify.wait(STREAM_POLL);
                }
            }
        }
    }
}

/// A QUIC bidirectional stream as one duplex [`SyncStream`](crate::common::stream::SyncStream).
///
/// A QUIC stream is handed out as two independent objects, but every engine
/// relay speaks one duplex stream. Pairing them is not a formality: the two
/// halves are separate handles to the same stream, so the relay can drive them
/// from two threads without a lock held across a blocking read. Each half keeps
/// its own `Mutex` purely because `std::io::Read`/`Write` take `&mut self` —
/// the shared state underneath is the connection's, and it is already
/// internally synchronized.
///
/// `shutdown(Write)` is a QUIC FIN, queued behind whatever the send buffer
/// still holds; the read half keeps working, which is what makes TCP half-close
/// semantics survive the round trip.
pub struct QuicStreamPair {
    send: parking_lot::Mutex<QuicSendStream>,
    recv: parking_lot::Mutex<QuicRecvStream>,
}

impl QuicStreamPair {
    /// Pair the two halves of one bidirectional stream.
    pub fn new(send: QuicSendStream, recv: QuicRecvStream) -> Self {
        Self {
            send: parking_lot::Mutex::new(send),
            recv: parking_lot::Mutex::new(recv),
        }
    }

    /// The peer's stream id, useful for logging a relay.
    pub fn id(&self) -> u64 {
        self.send.lock().id()
    }
}

impl io::Read for QuicStreamPair {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut *self.recv.lock(), buf)
    }
}

impl io::Write for QuicStreamPair {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut *self.send.lock(), buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut *self.send.lock())
    }
}

impl crate::common::stream::SyncStream for QuicStreamPair {
    fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        if matches!(how, std::net::Shutdown::Write | std::net::Shutdown::Both) {
            self.send.lock().finish()?;
        }
        Ok(())
    }
}
