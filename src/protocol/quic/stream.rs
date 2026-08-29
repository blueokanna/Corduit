//! QUIC stream handles (`AsyncRead` / `AsyncWrite`) over a shared
//! [`QuicConn`].

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::error::QuicError;
use super::transport::{QuicConn, RecvOutcome};

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

    fn io_err(e: &QuicError) -> io::Error {
        io::Error::other(e.to_string())
    }
}

impl AsyncWrite for QuicSendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            let mut st = this.conn.lock();
            if let Some(e) = &st.closed {
                return Poll::Ready(Err(Self::io_err(e)));
            }
            match this.conn.send_data(&mut st, this.stream_id, buf) {
                Ok(n) => {
                    // Wake the driver so the new data hits the wire.
                    this.conn.writer.notify_one();
                    return Poll::Ready(Ok(n));
                }
                Err(QuicError::StreamLimit) => {
                    // Send buffer full: wait for ACKs / flow control.
                    let notify = this.conn.stream_send_notify(&st, this.stream_id);
                    drop(st);
                    let mut fut = Box::pin(notify.notified());
                    if std::future::Future::poll(fut.as_mut(), cx).is_pending() {
                        return Poll::Pending;
                    }
                }
                Err(e) => return Poll::Ready(Err(Self::io_err(&e))),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let st = this.conn.lock();
            if let Some(e) = &st.closed {
                return Poll::Ready(Err(Self::io_err(e)));
            }
            if this.conn.send_buffered(&st, this.stream_id) == 0 {
                return Poll::Ready(Ok(()));
            }
            let notify = this.conn.stream_send_notify(&st, this.stream_id);
            drop(st);
            let mut fut = Box::pin(notify.notified());
            if std::future::Future::poll(fut.as_mut(), cx).is_pending() {
                return Poll::Pending;
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut st = this.conn.lock();
        if let Some(e) = &st.closed {
            return Poll::Ready(Err(Self::io_err(e)));
        }
        match this.conn.fin_stream(&mut st, this.stream_id) {
            Ok(()) => {
                this.conn.writer.notify_one();
                Poll::Ready(Ok(()))
            }
            Err(e) => Poll::Ready(Err(Self::io_err(&e))),
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

impl AsyncRead for QuicRecvStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let mut st = this.conn.lock();
            if let Some(e) = &st.closed {
                return Poll::Ready(Err(Self::io_err(e)));
            }
            let unfilled = buf.initialize_unfilled();
            match this.conn.recv_into(&mut st, this.stream_id, unfilled) {
                RecvOutcome::Data(n) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                RecvOutcome::Eof => return Poll::Ready(Ok(())),
                RecvOutcome::Reset(code) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        format!("QUIC stream reset by peer (code {code})"),
                    )))
                }
                RecvOutcome::WouldBlock => {
                    let notify = this.conn.stream_recv_notify(&st, this.stream_id);
                    drop(st);
                    let mut fut = Box::pin(notify.notified());
                    if std::future::Future::poll(fut.as_mut(), cx).is_pending() {
                        return Poll::Pending;
                    }
                }
            }
        }
    }
}
