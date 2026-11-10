//! One socket path for recursive DNS, encrypted DNS and HTTP providers.
use std::sync::Once;
use std::time::Duration;

pub fn install() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let factory = courierust::courierust_net::outbound::SocketFactory {
            tcp: |address, timeout| {
                crate::common::socket::connect(address, timeout.unwrap_or(Duration::from_secs(10)))
            },
            udp: |bind, destination| {
                crate::common::socket::udp_bind_for(
                    bind,
                    Duration::from_secs(5),
                    Some(destination.ip()),
                )
            },
        };
        if courierust::courierust_net::outbound::install(factory).is_err() {
            tracing::warn!("An outbound socket factory was installed before Corduit");
        }
    });
}
