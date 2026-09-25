//! The client-facing DNS listener.
//!
//! `dns.enable` and `dns.listen` exist in every Corduit profile. Until this
//! module existed they were parsed, validated, plumbed through the RPC and FFI
//! layers — and then ignored, because nothing ever started a listener. A setting
//! that reads as if it works and does nothing is worse than one that is
//! rejected: the operator debugs the wrong layer.
//!
//! # What it answers
//!
//! It is a thin binding of [`recurse_x::Server`] around the resolver built by
//! [`crate::dns::engine_resolver::client_resolver`]: the profile's
//! `nameservers`, `nameserver-policy`, `hosts` and hostname bootstrap, with
//! RecurseX's answer-quality filter armed from `fallback` and
//! `fallback-filter`. RecurseX brings the UDP and TCP loops, the bounded
//! handler pool, per-client token-bucket rate limiting and query validation —
//! so this module owns only *where* to bind and *when* to stop.
//!
//! # What it deliberately does not do
//!
//! - **Fake-IP.** A synthesized address is only useful to something that can map
//!   it back, and the only component here that can is the netstack's responder,
//!   which allocates from its own pool for TUN traffic. A listener that handed a
//!   client an address nothing can reverse would be strictly worse than one that
//!   answers with the real address. `enhanced-mode: fake-ip` therefore belongs
//!   to `netstack`, and the engine says so when a profile sets both.
//! - **DNSSEC.** RecurseX validates RSASHA256 end to end but ships no root trust
//!   anchor, so the honest verdict for an unanchored chain is `Indeterminate`.
//!   Asking for validation without an anchor would cost CPU and change no
//!   answer, which is why the `dnssec` feature is not compiled in.

use std::net::SocketAddr;
use std::sync::Arc;

use recurse_x::{Resolver, Server, ServerConfig};
use tracing::info;

/// Cap on concurrent TCP queries a listener will serve.
///
/// A TCP query costs a thread for as long as its client keeps the connection
/// open, so this cap is a thread bound. RecurseX's default (1024) is sized for a
/// resolver serving a network; a listener is bound to one address that a local
/// client reaches, and 64 concurrent queries is already more than a stub
/// resolver generates. The idle timeout still reclaims a parked connection, so
/// this bounds the burst rather than the total.
const MAX_TCP_CONNECTIONS: usize = 64;

/// A running client-facing DNS listener.
pub struct DnsServer {
    server: Arc<Server>,
    /// The addresses it actually bound, in the order it bound them.
    ///
    /// Recorded rather than assumed: a configured port of `0` is resolved by the
    /// binder, and keeping what it chose is what makes the listener testable
    /// without a fixed port.
    bound: Vec<SocketAddr>,
}

impl DnsServer {
    /// Bind and start.
    ///
    /// UDP **and** TCP, always. A truncated UDP answer is a client's only signal
    /// to retry over TCP (RFC 7766 §5), and a listener that speaks only UDP
    /// hands out truncation with nowhere to go — so there is no knob for it.
    pub fn start(resolver: Arc<Resolver>, listen: SocketAddr) -> std::io::Result<Self> {
        let config = ServerConfig {
            max_tcp_connections: MAX_TCP_CONNECTIONS,
            ..ServerConfig::default()
        };
        let server = Arc::new(Server::with_config((*resolver).clone(), config));
        let bound = match server
            .bind_udp(listen)
            .and_then(|udp| server.bind_tcp(udp).map(|tcp| (udp, tcp)))
        {
            Ok((udp, tcp)) => vec![udp, tcp],
            Err(error) => {
                server.shutdown();
                server.join();
                return Err(error);
            }
        };

        info!(
            "DNS listener serving {} over UDP and TCP",
            bound
                .iter()
                .map(SocketAddr::to_string)
                .collect::<Vec<_>>()
                .join(" / ")
        );

        Ok(Self { server, bound })
    }

    /// The addresses the listener is bound to.
    pub fn bound(&self) -> &[SocketAddr] {
        &self.bound
    }

    /// Datagrams dropped because the handler pool was saturated.
    ///
    /// Non-zero means the listener is answering slower than it is being asked,
    /// which is the one number that separates "the client is broken" from "the
    /// listener is".
    pub fn shed(&self) -> u64 {
        self.server.udp_shed()
    }

    /// Stop and wait for every loop to exit.
    pub fn stop(&self) {
        self.server.shutdown();
        self.server.join();
        info!("DNS listener stopped");
    }
}

impl Drop for DnsServer {
    /// A safety net for a listener dropped without [`DnsServer::stop`].
    ///
    /// It signals but does not join: a `Drop` that blocks needs a reason, and
    /// every loop notices the flag within 100 ms, so the threads end with or
    /// without the join. [`DnsServer::stop`] is what an orderly shutdown calls.
    fn drop(&mut self) {
        self.server.shutdown();
    }
}

impl std::fmt::Debug for DnsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsServer")
            .field("bound", &self.bound)
            .field("shed", &self.shed())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::engine_resolver::{client_resolver, EngineDnsSettings};
    use recurse_x::{Message, Name, RData, RrType};
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{TcpStream, UdpSocket};
    use std::time::Duration;

    /// A query for `name`, ready to put on the wire.
    fn query_for(name: &str) -> Vec<u8> {
        Message::query(
            0x4242,
            Name::from_ascii(name).expect("name"),
            RrType::A,
            true,
        )
        .to_bytes()
        .expect("encode")
    }

    fn ask_udp(addr: SocketAddr, query: &[u8]) -> Vec<u8> {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind a client socket");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        socket.send_to(query, addr).expect("send");
        let mut buf = vec![0u8; 4096];
        let (len, _) = socket.recv_from(&mut buf).expect("recv");
        buf.truncate(len);
        buf
    }

    fn ask_tcp(addr: SocketAddr, query: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(addr).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .expect("length prefix");
        stream.write_all(query).expect("query");
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).expect("length prefix");
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut buf).expect("body");
        buf
    }

    /// A listener built from `settings`, bound to an ephemeral port.
    fn listener(settings: EngineDnsSettings) -> DnsServer {
        let resolver = client_resolver(settings).expect("a resolver can be built");
        DnsServer::start(resolver, "127.0.0.1:0".parse().expect("loopback"))
            .expect("the listener binds a loopback port")
    }

    /// The profile's `hosts` pin answers over both transports.
    ///
    /// The pin is what proves the answer came from the listener rather than from
    /// the network: the only configured upstream is a TEST-NET-1 address
    /// (RFC 5737), so a query that reached a server would time out instead.
    #[test]
    fn a_pinned_name_is_answered_over_udp_and_tcp() {
        let mut hosts = HashMap::new();
        hosts.insert(
            "pinned.example".to_string(),
            "203.0.113.9".parse().expect("ip"),
        );
        let server = listener(EngineDnsSettings {
            nameservers: vec!["udp://192.0.2.53:53".to_string()],
            hosts,
            ..EngineDnsSettings::default()
        });

        assert_eq!(server.bound().len(), 2);
        assert_ne!(server.bound()[0].port(), 0);
        assert_eq!(server.bound()[0].port(), server.bound()[1].port());

        let query = query_for("pinned.example");
        for reply in [
            ask_udp(server.bound()[0], &query),
            ask_tcp(server.bound()[1], &query),
        ] {
            let reply = Message::parse(&reply).expect("a parsable reply");
            assert_eq!(reply.id, 0x4242, "the transaction id is echoed");
            assert!(reply.flags.qr, "a reply, not a query");
            assert_eq!(reply.answers.len(), 1, "exactly the pin");
            assert_eq!(
                reply.answers[0].rdata,
                RData::A("203.0.113.9".parse().expect("ip"))
            );
        }

        assert_eq!(server.shed(), 0, "nothing should have been dropped");
        server.stop();
    }

    /// `nameserver-policy` reaches a listener the same way it reaches the
    /// engine: the policy group answers, not the default group.
    #[test]
    fn a_policy_group_answers_a_listener() {
        let (port, handle) = crate::dns::engine_resolver::testing::spawn_udp_server(|_| {
            Some([203, 0, 113, 7].into())
        });

        let mut policy = HashMap::new();
        policy.insert(
            "+.node.test".to_string(),
            vec![format!("udp://127.0.0.1:{port}")],
        );
        let server = listener(EngineDnsSettings {
            nameservers: vec!["udp://127.0.0.1:1".to_string()],
            policy,
            ..EngineDnsSettings::default()
        });

        let reply = Message::parse(&ask_udp(server.bound()[0], &query_for("entry.node.test")))
            .expect("a parsable reply");
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(
            reply.answers[0].rdata,
            RData::A("203.0.113.7".parse().expect("ip"))
        );

        server.stop();
        drop(handle);
    }

    /// A listener must not answer with an address nothing can reverse: fake-IP
    /// belongs to the netstack's responder, which owns the pool that maps a
    /// synthetic address back to a name.
    #[test]
    fn a_listener_never_synthesizes_a_fake_address() {
        let mut hosts = HashMap::new();
        hosts.insert(
            "real.example".to_string(),
            "198.18.0.9".parse().expect("ip"),
        );
        let server = listener(EngineDnsSettings {
            nameservers: vec!["udp://192.0.2.53:53".to_string()],
            hosts,
            ..EngineDnsSettings::default()
        });

        let reply = Message::parse(&ask_udp(server.bound()[0], &query_for("real.example")))
            .expect("a parsable reply");
        assert_eq!(
            reply.answers[0].rdata,
            RData::A("198.18.0.9".parse().expect("ip"))
        );
        server.stop();
    }
}
