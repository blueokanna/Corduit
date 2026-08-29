//! Bridge a blocking (synchronous) duplex stream into the tokio async world.
//!
//! courierust's TLS and QUIC layers are synchronous: [`TlsConnector::connect`]
//! returns a blocking [`TlsStream`] and its HTTP codecs read/write blocking
//! sockets. The Corduit engine, however, is asynchronous (tokio). This module
//! is the seam between the two worlds: it wraps any blocking
//! `Read + Write` stream and presents it as an [`AsyncRead`] + [`AsyncWrite`]
//! value the engine can relay through with the usual `tokio::io` combinators.
//!
//! # Design: one owner thread, zero lock contention
//!
//! A single dedicated thread owns the blocking stream. Its loop is:
//!
//! 1. drain every pending write from the async side (non-blocking),
//! 2. attempt a read (the socket carries a short read timeout),
//! 3. park on the write channel with a short timeout.
//!
//! Because reads and writes are serviced by the *same* thread, there is no
//! `Mutex` and therefore no reader/writer starvation — the failure mode of a
//! naive shared-lock design under sustained bidirectional load. The async
//! side never blocks: [`AsyncWrite::poll_write`] reserves channel capacity
//! and hands bytes over; [`AsyncRead::poll_read`] drains a bounded channel.
//!
//! Backpressure is real in both directions: when the read channel fills, the
//! owner thread blocks in `blocking_send`, which stops reading the socket,
//! which stalls the peer. When the write channel fills, `poll_write` returns
//! `Pending` and the caller is woken when a slot frees.
//!
//! The socket read timeout bounds write latency when the peer is idle:
//! a write queued while the owner thread is blocked in `read()` is picked up
//! within that interval. The timeout is short (~20 ms) so the bound is small;
//! courierust's TLS record layer tolerates `Timeout` mid-record — it resumes
//! from the exact byte, never treating a transient timeout as fatal.
//!
//! # Shutdown
//!
//! [`AsyncWrite::poll_shutdown`] forwards a graceful-shutdown message that
//! runs an optional hook (used to emit a TLS `close_notify`); the owner
//! thread then keeps reading until the peer closes (TLS half-close). Dropping
//! the adapter closes both channels, which terminates the thread and releases
//! the stream.
//!
//! [`TlsConnector::connect`]: courierust::courierust_tls::TlsConnector::connect
//! [`TlsStream`]: courierust::courierust_tls::TlsStream

use courierust::courierust_error::ErrorKind as CourierErrorKind;
use courierust::courierust_io::{Read as CRead, Write as CWrite};
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// Optional graceful-shutdown hook run by the owner thread (e.g. emitting a
/// TLS `close_notify`).
pub(crate) type ShutdownHook<S> = Box<dyn FnOnce(&mut S) + Send>;

/// Byte buffer size used by the owner thread (also the max `poll_write`
/// message size accepted in one chunk).
const IO_CHUNK: usize = 16 * 1024;

/// Idle poll interval: bounds write latency while the peer is silent and
/// the read channel is idle. The socket read timeout is set to this value
/// by the caller.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Message produced by the owner thread (read direction).
enum ReadMsg {
    /// A chunk of application data read off the stream.
    Data(Vec<u8>),
    /// Clean end-of-stream (peer closed / TLS close_notify received).
    Eof,
    /// The stream failed.
    Err(io::Error),
}

/// Message consumed by the owner thread (write direction).
enum WriteMsg {
    /// Application data to write (written in full before the next message).
    Data(Vec<u8>),
    /// Flush the underlying writer.
    Flush,
    /// Graceful shutdown (run the optional hook, then keep reading).
    Shutdown,
}

struct Inner {
    /// Set when the owner thread hit a fatal error; surfaced by
    /// `poll_write` / `poll_flush`.
    write_error: Mutex<Option<io::Error>>,
}

/// An [`AsyncRead`] + [`AsyncWrite`] adapter over a blocking duplex stream.
///
/// `S` is typically
/// `courierust::courierust_tls::TlsStream<Arc<TcpStream>, Arc<TcpStream>>`
/// or any `std`-based stream implementing courierust's `Read`/`Write`.
pub struct BlockingStream<S> {
    inner: Arc<Inner>,
    read_rx: mpsc::Receiver<ReadMsg>,
    write_tx: mpsc::Sender<WriteMsg>,
    /// Bytes received but not yet handed to `poll_read`.
    read_pending: VecDeque<u8>,
    /// Whether `poll_shutdown` was called.
    write_closed: bool,
    /// The stream itself is owned by the worker thread; the parameter keeps
    /// the concrete transport type in the type system (covariant marker).
    _stream: PhantomData<fn() -> S>,
    _thread: Option<std::thread::JoinHandle<()>>,
}

/// Returns whether a courierust error is transient and must be retried.
fn is_retryable(e: &CourierErrorKind) -> bool {
    matches!(e, CourierErrorKind::Timeout | CourierErrorKind::WouldBlock)
}

/// Converts a courierust error into an `io::Error`.
fn to_io_error(e: courierust::courierust_error::Error) -> io::Error {
    io::Error::other(e.to_string())
}

impl<S: CRead + CWrite + Send + 'static> BlockingStream<S> {
    /// Wrap `stream`. `read_capacity` bounds the in-flight read chunks
    /// (backpressure); `shutdown_hook` is run by the owner thread on
    /// graceful shutdown (e.g. sending a TLS `close_notify`).
    ///
    /// The caller must configure `stream`'s underlying socket with a short
    /// read timeout ([`POLL_INTERVAL`]) before handing it in.
    ///
    /// # Panics
    ///
    /// Panics if the owner thread cannot be spawned.
    pub fn new(stream: S, read_capacity: usize, shutdown_hook: Option<ShutdownHook<S>>) -> Self {
        let inner = Arc::new(Inner {
            write_error: Mutex::new(None),
        });

        let (read_tx, read_rx) = mpsc::channel::<ReadMsg>(read_capacity.max(1));
        let (write_tx, mut write_rx) = mpsc::channel::<WriteMsg>(64);

        let owner_inner = inner.clone();
        let thread = std::thread::Builder::new()
            .name("corduit-blocking-owner".into())
            .spawn(move || {
                let mut stream = stream;
                let mut buf = vec![0u8; IO_CHUNK];
                let mut shutdown_hook = shutdown_hook;
                let mut write_gone = false;

                loop {
                    // 1. Drain every pending write (never blocks the read
                    //    fast path).
                    loop {
                        match write_rx.try_recv() {
                            Ok(WriteMsg::Data(bytes)) => {
                                if let Err(e) = write_full(&mut stream, &bytes) {
                                    *owner_inner.write_error.lock().unwrap() = Some(e);
                                }
                            }
                            Ok(WriteMsg::Flush) => {
                                if let Err(e) = CWrite::flush(&mut stream) {
                                    if !is_retryable(&e.kind) {
                                        *owner_inner.write_error.lock().unwrap() =
                                            Some(to_io_error(e));
                                    }
                                }
                            }
                            Ok(WriteMsg::Shutdown) => {
                                if let Some(hook) = shutdown_hook.take() {
                                    hook(&mut stream);
                                }
                            }
                            Err(mpsc::error::TryRecvError::Empty) => break,
                            Err(mpsc::error::TryRecvError::Disconnected) => {
                                write_gone = true;
                                break;
                            }
                        }
                    }

                    if write_gone && read_tx.is_closed() {
                        break;
                    }

                    match CRead::read(&mut stream, &mut buf) {
                        Ok(n) if n > 0 => {
                            let chunk = buf[..n].to_vec();
                            if read_tx.blocking_send(ReadMsg::Data(chunk)).is_err() {
                                break; // async side dropped the receiver
                            }
                            continue; // fast path: keep draining both sides
                        }
                        Ok(_) => {
                            let _ = read_tx.blocking_send(ReadMsg::Eof);
                            break;
                        }
                        Err(e) if is_retryable(&e.kind) => {}
                        Err(e) if matches!(e.kind, CourierErrorKind::UnexpectedEof) => {
                            let _ = read_tx.blocking_send(ReadMsg::Eof);
                            break;
                        }
                        Err(e) => {
                            let _ = read_tx.blocking_send(ReadMsg::Err(to_io_error(e)));
                            break;
                        }
                    }
                    std::thread::sleep(POLL_INTERVAL);
                }
            })
            .expect("spawn corduit-blocking-owner");

        Self {
            inner,
            read_rx,
            write_tx,
            read_pending: VecDeque::new(),
            write_closed: false,
            _stream: PhantomData,
            _thread: Some(thread),
        }
    }
}

/// Write a buffer in full over a courierust writer.
fn write_full<W: CWrite>(writer: &mut W, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        match CWrite::write(writer, data) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "blocking write returned 0 bytes",
                ))
            }
            Ok(n) => data = &data[n..],
            Err(e) if is_retryable(&e.kind) => std::thread::sleep(POLL_INTERVAL),
            Err(e) => return Err(to_io_error(e)),
        }
    }
    Ok(())
}

impl<S: CRead + CWrite + Send + 'static> AsyncRead for BlockingStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_pending.is_empty() {
            let n = std::cmp::min(buf.remaining(), self.read_pending.len());
            for b in self.read_pending.drain(..n) {
                buf.put_slice(&[b]);
            }
            return Poll::Ready(Ok(()));
        }

        match std::pin::Pin::new(&mut self.read_rx).poll_recv(cx) {
            Poll::Ready(Some(ReadMsg::Data(chunk))) => {
                if chunk.len() <= buf.remaining() {
                    buf.put_slice(&chunk);
                } else {
                    let n = buf.remaining();
                    buf.put_slice(&chunk[..n]);
                    self.read_pending.extend(chunk[n..].iter().copied());
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(ReadMsg::Eof)) | Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Ready(Some(ReadMsg::Err(e))) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: CRead + CWrite + Send + 'static> AsyncWrite for BlockingStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream shutdown",
            )));
        }
        // Surface a fatal owner-thread error if one happened.
        if let Some(e) = self.inner.write_error.lock().unwrap().take() {
            return Poll::Ready(Err(e));
        }
        let mut slot = std::pin::pin!(self.write_tx.reserve());
        match slot.as_mut().poll(cx) {
            Poll::Ready(Ok(permit)) => {
                let data = buf.to_vec();
                let n = data.len();
                permit.send(WriteMsg::Data(data));
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "writer channel closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        if let Some(e) = self.inner.write_error.lock().unwrap().take() {
            return Poll::Ready(Err(e));
        }
        let mut slot = std::pin::pin!(self.write_tx.reserve());
        match slot.as_mut().poll(cx) {
            Poll::Ready(Ok(permit)) => {
                permit.send(WriteMsg::Flush);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "writer channel closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        self.write_closed = true;
        let mut slot = std::pin::pin!(self.write_tx.reserve());
        match slot.as_mut().poll(cx) {
            Poll::Ready(Ok(permit)) => {
                permit.send(WriteMsg::Shutdown);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "writer channel closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A plain `TcpStream` implements courierust's `Read`/`Write` only via
    /// `&TcpStream` / `Arc<TcpStream>`, so we wrap every socket in an `Arc`
    /// (the same shape the real TLS transport uses) and apply the bridge's
    /// short read timeout.
    fn socket_pair() -> (Arc<TcpStream>, Arc<TcpStream>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = Arc::new(TcpStream::connect(addr).unwrap());
        let (server, _) = listener.accept().unwrap();
        (client, Arc::new(server))
    }

    #[tokio::test]
    async fn round_trip_echo() {
        let (peer, stream) = socket_pair();
        stream.set_read_timeout(Some(POLL_INTERVAL)).unwrap();
        let bridge = BlockingStream::new(stream, 8, None);

        let raw_peer = Arc::try_unwrap(peer).unwrap();
        raw_peer.set_nonblocking(true).unwrap();
        let mut client = tokio::net::TcpStream::from_std(raw_peer).unwrap();
        const PAYLOAD: &[u8] = b"hello bridge"; // 12 bytes
        let server = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let mut total = 0;
            while total < PAYLOAD.len() {
                match client.read(&mut buf[total..]).await {
                    Ok(0) => break,
                    Ok(n) => total += n,
                    Err(_) => break,
                }
            }
            client.write_all(&buf[..total]).await.unwrap();
            total
        });

        let mut bridge = bridge;
        bridge.write_all(PAYLOAD).await.unwrap();
        let mut resp = Vec::new();
        bridge.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp, PAYLOAD);
        assert_eq!(server.await.unwrap(), PAYLOAD.len());
    }

    #[tokio::test]
    async fn eof_surfaces_as_zero_read() {
        let (peer, stream) = socket_pair();
        stream.set_read_timeout(Some(POLL_INTERVAL)).unwrap();
        let bridge = BlockingStream::new(stream, 8, None);

        // Drop the peer: the owner thread should observe EOF.
        drop(peer);

        let mut bridge = bridge;
        let mut buf = [0u8; 64];
        let n = bridge.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn shutdown_runs_hook_and_closes() {
        let (peer, stream) = socket_pair();
        stream.set_read_timeout(Some(POLL_INTERVAL)).unwrap();

        let (hook_tx, hook_rx) = std::sync::mpsc::channel::<()>();
        let bridge = BlockingStream::new(
            stream,
            8,
            Some(Box::new(move |_s: &mut Arc<TcpStream>| {
                let _ = hook_tx.send(());
            })),
        );
        let mut bridge = bridge;
        bridge.shutdown().await.unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while hook_rx.try_recv().is_err() {
            assert!(
                std::time::Instant::now() < deadline,
                "shutdown hook did not run within 5s"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        drop(peer);
        drop(bridge);
    }

    #[test]
    fn writer_and_reader_share_stream_concurrently() {
        let (peer, stream) = socket_pair();
        stream.set_read_timeout(Some(POLL_INTERVAL)).unwrap();

        // Echo server on the raw peer end.
        let echo_handle = std::thread::spawn(move || {
            let mut peer = Arc::try_unwrap(peer).unwrap();
            let mut buf = [0u8; 4096];
            let mut total = 0;
            loop {
                match std::io::Read::read(&mut peer, &mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        total += n;
                        if std::io::Write::write_all(&mut peer, &buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            total
        });

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut bridge = BlockingStream::new(stream, 8, None);
            let payload = vec![0x5au8; 64 * 1024];
            let mut written = 0;
            let mut received = Vec::new();
            let mut buf = [0u8; 4096];
            while written < payload.len() {
                let n = std::cmp::min(4096, payload.len() - written);
                bridge
                    .write_all(&payload[written..written + n])
                    .await
                    .unwrap();
                written += n;
                match bridge.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => received.extend_from_slice(&buf[..n]),
                    Err(_) => break,
                }
            }
            // Drain whatever the echo still has in flight.
            while received.len() < payload.len() {
                match bridge.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => received.extend_from_slice(&buf[..n]),
                    Err(_) => break,
                }
            }
            assert_eq!(received, payload);
        });

        assert_eq!(echo_handle.join().unwrap(), 64 * 1024);
    }
}
