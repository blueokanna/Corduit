//! RecurseX and Courierust must resolve to the same socket-factory instance.
#![cfg(feature = "std")]

use recurse_x::transport::{DnsTransport, Transports};
use recurse_x::upstream::{Endpoint, Proto};
use recurse_x::{message::Message, name::Name, qtype::RrType};
use std::sync::atomic::{AtomicUsize, Ordering};
static TCP: AtomicUsize = AtomicUsize::new(0);
static UDP: AtomicUsize = AtomicUsize::new(0);

#[test]
fn dns_and_http_use_the_installed_socket_factory() {
    let factory = courierust::courierust_net::outbound::SocketFactory {
        tcp: |_, _| {
            TCP.fetch_add(1, Ordering::Relaxed);
            Err(std::io::ErrorKind::PermissionDenied.into())
        },
        udp: |_, _| {
            UDP.fetch_add(1, Ordering::Relaxed);
            Err(std::io::ErrorKind::PermissionDenied.into())
        },
    };
    assert!(courierust::courierust_net::outbound::install(factory).is_ok());
    let generation = courierust::courierust_net::outbound::generation();
    assert!(courierust::courierust_net::outbound::install(factory).is_err());
    assert_eq!(
        courierust::courierust_net::outbound::generation(),
        generation
    );
    courierust::courierust_net::outbound::network_changed();
    assert_eq!(
        courierust::courierust_net::outbound::generation(),
        generation.wrapping_add(1)
    );
    let transports = Transports::new();
    let address = "192.0.2.1".parse().unwrap();
    // DoQ validates the question before opening a socket. Use a real query so
    // every transport reaches the factory rather than failing during parsing.
    let query = Message::query(
        1,
        Name::from_ascii("example.test").unwrap(),
        RrType::A,
        true,
    )
    .to_bytes()
    .unwrap();
    assert!(
        transports
            .udp
            .exchange(&query, &Endpoint::new(address, 53, Proto::Udp), 100)
            .is_err()
    );
    assert!(
        transports
            .tcp
            .exchange(&query, &Endpoint::new(address, 53, Proto::Tcp), 100)
            .is_err()
    );
    assert_eq!(UDP.load(Ordering::Relaxed), 1);
    assert_eq!(TCP.load(Ordering::Relaxed), 1);

    // Reject at socket creation: no TLS handshake or external network is needed.
    // Verification is disabled only in these fixtures, whose factory never
    // returns a socket. Each protocol must reach the same installed callback.
    use courierust::courierust_tls::RootStore;
    use recurse_x::transports::{doh::DohTransport, doh3::Doh3Transport};
    use recurse_x::transports::{doq::DoqTransport, dot::DotTransport};
    let encrypted: [(Box<dyn DnsTransport>, Proto, bool); 4] = [
        (
            Box::new(DotTransport::for_host(
                "192.0.2.1",
                RootStore::new(),
                false,
                0,
            )),
            Proto::Tls,
            false,
        ),
        (
            Box::new(DohTransport::for_host(
                "192.0.2.1",
                RootStore::new(),
                false,
                0,
            )),
            Proto::DoH,
            false,
        ),
        (
            Box::new(Doh3Transport::for_host(
                "192.0.2.1",
                RootStore::new(),
                false,
                0,
            )),
            Proto::DoH3,
            true,
        ),
        (
            Box::new(DoqTransport::for_host(
                "192.0.2.1",
                RootStore::new(),
                false,
                0,
            )),
            Proto::DoQ,
            true,
        ),
    ];
    for (transport, protocol, datagram) in encrypted {
        let counter = if datagram { &UDP } else { &TCP };
        let before = counter.load(Ordering::Relaxed);
        assert!(
            transport
                .exchange(&query, &Endpoint::new(address, 853, protocol), 100)
                .is_err()
        );
        assert!(
            counter.load(Ordering::Relaxed) > before,
            "{protocol:?} bypassed the socket factory"
        );
    }
    let client = courierust::courierust_client::Client::with_config(Default::default());
    let before = TCP.load(Ordering::Relaxed);
    assert!(
        client
            .request(
                "http://192.0.2.1/",
                courierust::courierust_http::Method::GET
            )
            .send()
            .is_err()
    );
    assert!(
        TCP.load(Ordering::Relaxed) > before,
        "HTTP bypassed the socket factory"
    );
}
