//! The public QUIC client facade: [`QuicClient`] establishes a connection
//! and hands out [`ClientConnection`] / stream handles.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use super::config::ClientConfig;
use super::error::{QuicError, Result};
use super::stream::{QuicRecvStream, QuicSendStream};
use super::transport::QuicConn;

/// A QUIC client endpoint that maintains (and reuses) one connection to its
/// configured server.
pub struct QuicClient {
    config: ClientConfig,
    conn: Mutex<Option<Arc<ClientConnection>>>,
}

impl QuicClient {
    /// Create a client for the given configuration.
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            conn: Mutex::new(None),
        }
    }

    /// The configuration.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Establish (or reuse) the connection. Blocks until the TLS 1.3-over-QUIC
    /// handshake completes.
    pub async fn connect(&self) -> Result<Arc<ClientConnection>> {
        {
            let guard = self.conn.lock().await;
            if let Some(c) = guard.as_ref() {
                if !c.is_closed() {
                    return Ok(c.clone());
                }
            }
        }

        let local = self
            .config
            .local_addr
            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
        let udp = UdpSocket::bind(local)
            .await
            .map_err(|e| QuicError::Io(format!("bind UDP: {e}")))?;
        udp.connect(self.config.server_addr)
            .await
            .map_err(|e| QuicError::Io(format!("connect UDP: {e}")))?;

        let conn = QuicConn::start(udp, self.config.server_addr, self.config.clone())?;
        let client = Arc::new(ClientConnection { conn });

        // Wait for the handshake.
        client.wait_handshake().await?;

        let mut guard = self.conn.lock().await;
        *guard = Some(client.clone());
        Ok(client)
    }

    /// The current connection, if any.
    pub async fn connection(&self) -> Option<Arc<ClientConnection>> {
        self.conn.lock().await.clone()
    }

    /// Close the connection, if any.
    pub async fn close(&self) {
        if let Some(c) = self.conn.lock().await.take() {
            c.close();
        }
    }
}

/// A live QUIC connection to the server.
pub struct ClientConnection {
    conn: Arc<QuicConn>,
}

impl ClientConnection {
    pub(crate) async fn wait_handshake(&self) -> Result<()> {
        loop {
            let mut rx = self.conn.handshake_rx.clone();
            {
                let st = self.conn.lock();
                if st.handshake_complete {
                    return Ok(());
                }
                if let Some(e) = &st.closed {
                    return Err(e.clone());
                }
            }
            if *rx.borrow() {
                continue; // an event happened; re-check state
            }
            let _ = rx.changed().await;
        }
    }

    /// Whether the connection has closed.
    pub fn is_closed(&self) -> bool {
        let st = self.conn.lock();
        st.closed.is_some()
    }

    /// The remote address.
    pub fn remote_address(&self) -> std::net::SocketAddr {
        self.conn.remote_address()
    }

    /// The current RTT estimate.
    pub fn rtt(&self) -> Duration {
        let st = self.conn.lock();
        self.conn.smoothed_rtt(&st)
    }

    /// Open a bidirectional stream (client-initiated).
    pub async fn open_bi(&self) -> Result<(QuicSendStream, QuicRecvStream)> {
        let id = loop {
            {
                let mut st = self.conn.lock();
                if self.conn.can_open(&st, false) {
                    break self.conn.open_bi(&mut st)?;
                }
                if let Some(e) = &st.closed {
                    return Err(e.clone());
                }
            }
            self.conn.streams_notify_handle().notified().await;
        };
        Ok((
            QuicSendStream::new(self.conn.clone(), id),
            QuicRecvStream::new(self.conn.clone(), id),
        ))
    }

    /// Open a unidirectional stream (client-initiated).
    pub async fn open_uni(&self) -> Result<QuicSendStream> {
        let id = loop {
            {
                let mut st = self.conn.lock();
                if self.conn.can_open(&st, true) {
                    break self.conn.open_uni(&mut st)?;
                }
                if let Some(e) = &st.closed {
                    return Err(e.clone());
                }
            }
            self.conn.streams_notify_handle().notified().await;
        };
        Ok(QuicSendStream::new(self.conn.clone(), id))
    }

    /// Wait for and return the next server-initiated unidirectional stream
    /// that has data (or a FIN) available.
    pub async fn accept_uni(&self) -> Result<QuicRecvStream> {
        loop {
            {
                let mut st = self.conn.lock();
                if let Some(id) = self.conn.accept_uni_ready(&mut st) {
                    return Ok(QuicRecvStream::new(self.conn.clone(), id));
                }
                if let Some(e) = &st.closed {
                    return Err(e.clone());
                }
            }
            self.conn.streams_notify_handle().notified().await;
        }
    }

    /// Send a datagram (RFC 9221). Bounded by the peer's UDP payload size.
    pub async fn send_datagram(&self, data: Vec<u8>) -> Result<()> {
        {
            let mut st = self.conn.lock();
            self.conn.send_datagram(&mut st, data)?;
        }
        self.conn.writer.notify_one();
        Ok(())
    }

    /// Receive a datagram (RFC 9221).
    pub async fn read_datagram(&self) -> Result<Vec<u8>> {
        loop {
            {
                let mut st = self.conn.lock();
                if let Some(d) = self.conn.pop_datagram(&mut st) {
                    return Ok(d);
                }
                if let Some(e) = &st.closed {
                    return Err(e.clone());
                }
            }
            self.conn.datagram_notify_handle().notified().await;
        }
    }

    /// Close the connection.
    pub fn close(&self) {
        let mut st = self.conn.lock();
        self.conn.close(&mut st, None);
    }

    /// Close the connection with an application error.
    pub fn close_with_error(&self, error_code: u64, reason: &str) {
        let mut st = self.conn.lock();
        self.conn.close(
            &mut st,
            Some(QuicError::ClosedByPeer {
                error_code,
                reason: reason.to_string(),
            }),
        );
    }
}
