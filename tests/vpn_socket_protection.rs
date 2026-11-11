//! Run on Android to exercise the actual socket creation and protection path.
#![cfg(all(feature = "std", target_os = "android"))]

use corduit::{common::socket, netstack};
use std::io::ErrorKind;
use std::net::{TcpListener, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

struct ResetVpnState;

impl Drop for ResetVpnState {
    fn drop(&mut self) {
        netstack::clear_android_vpn_fd();
        netstack::clear_protect_callback();
    }
}

#[test]
fn tcp_and_udp_require_protection_while_vpn_is_active() {
    // The descriptor is only an active-VPN marker; no TUN or elevated access
    // is needed. This test owns it until the state has been cleared.
    let marker = UdpSocket::bind("127.0.0.1:0").unwrap();
    let _reset = ResetVpnState;
    netstack::set_android_vpn_fd(marker.as_raw_fd());
    netstack::clear_protect_callback();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let destination = listener.local_addr().unwrap();
    let timeout = Duration::from_secs(1);
    let bind = "127.0.0.1:0".parse().unwrap();
    let assert_denied = || {
        assert_eq!(
            socket::connect(&destination, timeout).unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            socket::udp_bind_for(bind, timeout, Some(destination.ip()))
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    };
    assert_denied();

    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let generation = courierust::courierust_net::outbound::generation();
    netstack::set_protect_callback(move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
        false
    });
    assert_ne!(
        courierust::courierust_net::outbound::generation(),
        generation
    );
    assert_denied();
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    netstack::set_protect_callback(|_| true);
    let tcp = socket::connect(&destination, timeout).unwrap();
    let _accepted = listener.accept().unwrap();
    let _udp = socket::udp_bind_for(bind, timeout, Some(destination.ip())).unwrap();
    drop(tcp);

    let generation = courierust::courierust_net::outbound::generation();
    netstack::clear_protect_callback();
    assert_ne!(
        courierust::courierust_net::outbound::generation(),
        generation
    );
    assert_denied();
    netstack::clear_android_vpn_fd();
}
