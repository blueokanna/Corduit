//! # Corduit
//!
//! A synchronous, no_std-ready unified network proxy engine written in Rust.
//!
//! This crate is a single package that internally groups its code into
//! cohesive modules (each with its own `mod.rs`):
//!
//! * [`common`]   — shared minimal utilities (sync scheduler, sockets,
//!   relay, timers, URL parsing, HTTP client).
//! * [`engine`]   — the proxy engine: config, routing, inbounds/outbounds,
//!   proxy groups, health checks, providers and traffic accounting.
//! * [`crypto`]   — cryptographic primitives (digests, AEAD, KDF, X25519…).
//! * [`dns`]      — DNS resolver, cache, fake-IP and DoH/DoT servers.
//! * [`netstack`] — userspace TCP/IP stack for TUN-based transparent proxy.
//! * [`protocol`] — wire protocols & transports (TLS, QUIC, WireGuard…).
//!
//! ## The synchronous model
//!
//! Corduit has **no async runtime**. Concurrency comes from courierust's
//! work-stealing thread pool (short tasks: accept dispatch, handshakes,
//! control plane) layered with dedicated threads for long-lived relays and
//! per-listener accept loops. There is no tokio anywhere in the dependency
//! tree — `cargo tree` shows zero `tokio` packages.
//!
//! ## `no_std`
//!
//! With `default-features = false` the crate compiles on `no_std + alloc`
//! targets: the [`crypto`] primitives, [`common::url`], and the pure wire
//! codecs in [`protocol`] (`address`, `qpack`, `error`) have zero OS
//! dependencies. The threaded networking layer (engine, netstack, DNS
//! servers, RPC, HTTP/TLS/QUIC transports) is gated behind the `std`
//! feature.
//!
//! ## Examples
//!
//! Runnable, offline-friendly examples live in [`examples/`](https://github.com/blueokanna/Corduit/tree/main/examples)
//! (listed in the docs sidebar on docs.rs):
//!
//! * `minimal` — smallest real proxy: one mixed inbound + DIRECT outbound.
//! * `typed_config` — full [`Config`] built in Rust, with proxy groups, rules
//!   and hot reload via [`engine::Corduit::reload`].
//! * `json_api` — the JSON-string facade ([`api::start_proxy_from_yaml`] and
//!   friends) with runtime status queries.
//! * `providers` — end-to-end `rule_providers` + `proxy_providers` using
//!   local files, a selector group with `use:`, and `rule-set` rules.
//! * `routing_modes` — direct / rule / global mode decisions through
//!   [`engine::routing::Router`], without binding any sockets.
//! * `rpc_server` — the loopback JSON-RPC server: `GET /health`,
//!   `POST /rpc` over raw TCP, and the shared [`rpc::dispatch`] table.
//!
//! Run any of them with `cargo run --example <name>`. Each one binds only to
//! `127.0.0.1` on a high port (override via `CORDUIT_PORT` /
//! `CORDUIT_RPC_PORT`) and makes no outbound network calls by default.

// HarmonyOS uses a non-standard `target_os = "ohos"` value.
#![allow(unexpected_cfgs)]
// The protocol core is `no_std + alloc`; make the allocator crate available
// crate-wide (also supplies `format!`, `vec!` etc. in no_std builds).
#![cfg_attr(not(feature = "std"), no_std)]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
mod logging;

#[cfg(feature = "std")]
use std::sync::Arc;

// --- no_std protocol core ---------------------------------------------------
pub mod common;
pub mod crypto;
pub mod protocol;

// --- threaded networking layer (std) ----------------------------------------
#[cfg(feature = "std")]
pub mod api;
#[cfg(feature = "std")]
mod error;
#[cfg(feature = "std")]
pub mod ffi;
#[cfg(feature = "std")]
pub mod rpc;
#[cfg(feature = "std")]
mod types;

#[cfg(feature = "std")]
pub mod dns;
#[cfg(feature = "std")]
pub mod engine;
#[cfg(feature = "std")]
pub mod netstack;

#[cfg(all(feature = "std", target_os = "android"))]
pub mod android_jni;

#[cfg(feature = "std")]
pub use api::*;
#[cfg(feature = "std")]
pub use error::*;
#[cfg(feature = "std")]
pub use types::*;

/// Re-export the engine entry point at the crate root for convenience.
#[cfg(feature = "std")]
pub use engine::Corduit;

#[cfg(feature = "std")]
static CORDUIT_INSTANCE: once_cell::sync::Lazy<Arc<parking_lot::RwLock<Option<Corduit>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(parking_lot::RwLock::new(None)));

#[cfg(feature = "std")]
pub(crate) static TUN_LIFECYCLE_LOCK: once_cell::sync::Lazy<parking_lot::Mutex<()>> =
    once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(()));

#[cfg(all(feature = "std", target_os = "android"))]
static ANDROID_VPN_PROCESSOR: once_cell::sync::Lazy<
    Arc<parking_lot::RwLock<Option<Arc<crate::netstack::AndroidVpnProcessor>>>>,
> = once_cell::sync::Lazy::new(|| Arc::new(parking_lot::RwLock::new(None)));

#[cfg(all(feature = "std", target_os = "android"))]
static ANDROID_TUN_DEVICE: once_cell::sync::Lazy<
    parking_lot::Mutex<Option<crate::netstack::TunDevice>>,
> = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(None));

#[cfg(all(feature = "std", target_os = "android"))]
static ANDROID_PACKET_TASK: once_cell::sync::Lazy<
    parking_lot::Mutex<Option<std::thread::JoinHandle<()>>>,
> = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(None));

/// Global Windows VPN processor for stats tracking
#[cfg(all(feature = "std", windows))]
static WINDOWS_VPN_PROCESSOR: once_cell::sync::Lazy<
    Arc<parking_lot::RwLock<Option<Arc<crate::netstack::WindowsVpnProcessor>>>>,
> = once_cell::sync::Lazy::new(|| Arc::new(parking_lot::RwLock::new(None)));

/// Global Windows route manager
#[cfg(all(feature = "std", windows))]
static WINDOWS_ROUTE_MANAGER: once_cell::sync::Lazy<
    Arc<parking_lot::RwLock<Option<crate::netstack::WindowsRouteManager>>>,
> = once_cell::sync::Lazy::new(|| Arc::new(parking_lot::RwLock::new(None)));

/// Global Windows TUN device
#[cfg(all(feature = "std", windows))]
static WINDOWS_TUN_DEVICE: once_cell::sync::Lazy<
    Arc<parking_lot::RwLock<Option<crate::netstack::TunDevice>>>,
> = once_cell::sync::Lazy::new(|| Arc::new(parking_lot::RwLock::new(None)));

#[cfg(all(feature = "std", target_os = "linux"))]
static LINUX_VPN_PROCESSOR: once_cell::sync::Lazy<
    parking_lot::RwLock<Option<Arc<crate::netstack::TunPacketProcessor>>>,
> = once_cell::sync::Lazy::new(|| parking_lot::RwLock::new(None));

#[cfg(all(feature = "std", target_os = "linux"))]
static LINUX_TUN_DEVICE: once_cell::sync::Lazy<
    parking_lot::Mutex<Option<crate::netstack::TunDevice>>,
> = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(None));

#[cfg(all(feature = "std", target_os = "linux"))]
static LINUX_ROUTE_MANAGER: once_cell::sync::Lazy<
    parking_lot::Mutex<Option<crate::netstack::RouteManager>>,
> = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(None));

#[cfg(all(feature = "std", target_os = "linux"))]
static LINUX_PACKET_TASK: once_cell::sync::Lazy<
    parking_lot::Mutex<Option<std::thread::JoinHandle<()>>>,
> = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(None));

/// Set the global Android VPN processor
#[cfg(all(feature = "std", target_os = "android"))]
pub fn set_android_vpn_processor(processor: Arc<crate::netstack::AndroidVpnProcessor>) {
    let mut guard = ANDROID_VPN_PROCESSOR.write();
    *guard = Some(processor);
    tracing::info!("Android VPN processor stored globally for stats tracking");
}

/// Clear the global Android VPN processor
#[cfg(all(feature = "std", target_os = "android"))]
pub fn clear_android_vpn_processor() {
    let mut guard = ANDROID_VPN_PROCESSOR.write();
    *guard = None;
    tracing::info!("Android VPN processor cleared");
}

/// Get the global Android VPN processor
#[cfg(all(feature = "std", target_os = "android"))]
pub fn get_android_vpn_processor() -> Option<Arc<crate::netstack::AndroidVpnProcessor>> {
    let guard = ANDROID_VPN_PROCESSOR.read();
    guard.clone()
}

#[cfg(all(feature = "std", target_os = "android"))]
pub fn set_android_tun_device(device: crate::netstack::TunDevice) {
    *ANDROID_TUN_DEVICE.lock() = Some(device);
}

#[cfg(all(feature = "std", target_os = "android"))]
pub fn take_android_tun_device() -> Option<crate::netstack::TunDevice> {
    ANDROID_TUN_DEVICE.lock().take()
}

#[cfg(all(feature = "std", target_os = "android"))]
pub fn set_android_packet_task(task: std::thread::JoinHandle<()>) {
    *ANDROID_PACKET_TASK.lock() = Some(task);
}

#[cfg(all(feature = "std", target_os = "android"))]
pub fn take_android_packet_task() -> Option<std::thread::JoinHandle<()>> {
    ANDROID_PACKET_TASK.lock().take()
}

#[cfg(all(feature = "std", target_os = "linux"))]
pub fn set_linux_vpn_processor(processor: Arc<crate::netstack::TunPacketProcessor>) {
    *LINUX_VPN_PROCESSOR.write() = Some(processor);
}

#[cfg(all(feature = "std", target_os = "linux"))]
pub fn get_linux_vpn_processor() -> Option<Arc<crate::netstack::TunPacketProcessor>> {
    LINUX_VPN_PROCESSOR.read().clone()
}

#[cfg(all(feature = "std", target_os = "linux"))]
pub fn take_linux_vpn_processor() -> Option<Arc<crate::netstack::TunPacketProcessor>> {
    LINUX_VPN_PROCESSOR.write().take()
}

#[cfg(all(feature = "std", target_os = "linux"))]
pub fn set_linux_tun_device(device: crate::netstack::TunDevice) {
    *LINUX_TUN_DEVICE.lock() = Some(device);
}

#[cfg(all(feature = "std", target_os = "linux"))]
pub fn take_linux_tun_device() -> Option<crate::netstack::TunDevice> {
    LINUX_TUN_DEVICE.lock().take()
}

#[cfg(all(feature = "std", target_os = "linux"))]
pub fn linux_tun_device_is_running() -> bool {
    LINUX_TUN_DEVICE
        .lock()
        .as_ref()
        .is_some_and(crate::netstack::TunDevice::is_running)
}

#[cfg(all(feature = "std", target_os = "linux"))]
pub fn set_linux_route_manager(manager: crate::netstack::RouteManager) {
    *LINUX_ROUTE_MANAGER.lock() = Some(manager);
}

#[cfg(all(feature = "std", target_os = "linux"))]
pub fn take_linux_route_manager() -> Option<crate::netstack::RouteManager> {
    LINUX_ROUTE_MANAGER.lock().take()
}

#[cfg(all(feature = "std", target_os = "linux"))]
pub fn set_linux_packet_task(task: std::thread::JoinHandle<()>) {
    *LINUX_PACKET_TASK.lock() = Some(task);
}

#[cfg(all(feature = "std", target_os = "linux"))]
pub fn take_linux_packet_task() -> Option<std::thread::JoinHandle<()>> {
    LINUX_PACKET_TASK.lock().take()
}

#[cfg(all(feature = "std", target_os = "linux"))]
pub fn linux_packet_task_is_running() -> bool {
    LINUX_PACKET_TASK
        .lock()
        .as_ref()
        .is_some_and(|task| !task.is_finished())
}

/// Set the global Windows VPN processor
#[cfg(all(feature = "std", windows))]
pub fn set_windows_vpn_processor(processor: Arc<crate::netstack::WindowsVpnProcessor>) {
    let mut guard = WINDOWS_VPN_PROCESSOR.write();
    *guard = Some(processor);
    tracing::info!("Windows VPN processor stored globally for stats tracking");
}

/// Clear the global Windows VPN processor
#[cfg(all(feature = "std", windows))]
pub fn clear_windows_vpn_processor() {
    let mut guard = WINDOWS_VPN_PROCESSOR.write();
    *guard = None;
    tracing::info!("Windows VPN processor cleared");
}

/// Get the global Windows VPN processor
#[cfg(all(feature = "std", windows))]
pub fn get_windows_vpn_processor() -> Option<Arc<crate::netstack::WindowsVpnProcessor>> {
    let guard = WINDOWS_VPN_PROCESSOR.read();
    guard.clone()
}

#[cfg(all(feature = "std", windows))]
pub fn take_windows_vpn_processor() -> Option<Arc<crate::netstack::WindowsVpnProcessor>> {
    WINDOWS_VPN_PROCESSOR.write().take()
}

/// Set the global Windows route manager
#[cfg(all(feature = "std", windows))]
pub fn set_windows_route_manager(manager: crate::netstack::WindowsRouteManager) {
    let mut guard = WINDOWS_ROUTE_MANAGER.write();
    *guard = Some(manager);
    tracing::info!("Windows route manager stored globally");
}

/// Get the global Windows route manager
#[cfg(all(feature = "std", windows))]
pub fn get_windows_route_manager(
) -> Option<parking_lot::MappedRwLockReadGuard<'static, crate::netstack::WindowsRouteManager>> {
    let guard = WINDOWS_ROUTE_MANAGER.read();
    if guard.is_some() {
        Some(parking_lot::RwLockReadGuard::map(guard, |opt| {
            opt.as_ref().unwrap()
        }))
    } else {
        None
    }
}

/// Get mutable access to the global Windows route manager
#[cfg(all(feature = "std", windows))]
pub fn get_windows_route_manager_mut(
) -> Option<parking_lot::MappedRwLockWriteGuard<'static, crate::netstack::WindowsRouteManager>> {
    let guard = WINDOWS_ROUTE_MANAGER.write();
    if guard.is_some() {
        Some(parking_lot::RwLockWriteGuard::map(guard, |opt| {
            opt.as_mut().unwrap()
        }))
    } else {
        None
    }
}

/// Clear the global Windows route manager
#[cfg(all(feature = "std", windows))]
pub fn clear_windows_route_manager() {
    let mut guard = WINDOWS_ROUTE_MANAGER.write();
    *guard = None;
    tracing::info!("Windows route manager cleared");
}

#[cfg(all(feature = "std", windows))]
pub fn take_windows_route_manager() -> Option<crate::netstack::WindowsRouteManager> {
    WINDOWS_ROUTE_MANAGER.write().take()
}

/// Set the global Windows TUN device
#[cfg(all(feature = "std", windows))]
pub fn set_windows_tun_device(device: crate::netstack::TunDevice) {
    let mut guard = WINDOWS_TUN_DEVICE.write();
    *guard = Some(device);
    tracing::info!("Windows TUN device stored globally");
}

/// Clear the global Windows TUN device
#[cfg(all(feature = "std", windows))]
pub fn clear_windows_tun_device() {
    let mut guard = WINDOWS_TUN_DEVICE.write();
    *guard = None;
    tracing::info!("Windows TUN device cleared");
}

/// Take the global Windows TUN device (removes it from global state)
#[cfg(all(feature = "std", windows))]
pub fn take_windows_tun_device() -> Option<crate::netstack::TunDevice> {
    let mut guard = WINDOWS_TUN_DEVICE.write();
    guard.take()
}

/// Get the global Corduit instance
#[cfg(feature = "std")]
fn get_corduit_instance() -> Result<Arc<parking_lot::RwLock<Option<Corduit>>>> {
    Ok(Arc::clone(&CORDUIT_INSTANCE))
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::types::*;
    use proptest::prelude::*;

    // Generators for DTO types
    fn arb_traffic_stats_dto() -> impl Strategy<Value = TrafficStatsDto> {
        (
            any::<u64>(),
            any::<u64>(),
            any::<u64>(),
            any::<u64>(),
            any::<u32>(),
            any::<u64>(),
        )
            .prop_map(
                |(
                    upload,
                    download,
                    total_upload,
                    total_download,
                    connection_count,
                    uptime_secs,
                )| {
                    TrafficStatsDto {
                        upload,
                        download,
                        total_upload,
                        total_download,
                        connection_count,
                        uptime_secs,
                    }
                },
            )
    }

    fn arb_connection_dto() -> impl Strategy<Value = ConnectionDto> {
        (
            "[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}",
            "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}:[0-9]{1,5}",
            "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}",
            proptest::option::of("[a-z]{3,10}\\.[a-z]{2,3}"),
            prop_oneof!["TCP", "UDP", "HTTP", "SOCKS5"],
            "[a-z]{3,10}",
            any::<u64>(),
            any::<u64>(),
            any::<i64>(),
            proptest::option::of("[A-Z]{3,10}"),
        )
            .prop_map(
                |(
                    id,
                    src_addr,
                    dst_addr,
                    dst_domain,
                    protocol,
                    outbound,
                    upload,
                    download,
                    start_time,
                    rule,
                )| {
                    ConnectionDto {
                        id,
                        src_addr,
                        dst_addr,
                        dst_domain,
                        protocol,
                        outbound,
                        upload,
                        download,
                        start_time,
                        rule,
                    }
                },
            )
    }

    fn arb_proxy_info_dto() -> impl Strategy<Value = ProxyInfoDto> {
        (
            "[a-z]{3,10}",
            prop_oneof![
                "direct",
                "reject",
                "shadowsocks",
                "vmess",
                "trojan",
                "wireguard"
            ],
            proptest::option::of("[a-z]{3,10}\\.[a-z]{2,3}"),
            proptest::option::of(1u16..65535u16),
            proptest::option::of(1u64..10000u64),
            any::<bool>(),
        )
            .prop_map(|(tag, protocol_type, server, port, latency_ms, alive)| {
                ProxyInfoDto {
                    tag,
                    protocol_type,
                    server,
                    port,
                    latency_ms,
                    alive,
                }
            })
    }

    fn arb_proxy_group_dto() -> impl Strategy<Value = ProxyGroupDto> {
        (
            "[a-z]{3,10}",
            prop_oneof!["selector", "url-test", "fallback", "load-balance"],
            proptest::collection::vec("[a-z]{3,10}", 1..5),
            "[a-z]{3,10}",
        )
            .prop_map(|(tag, group_type, proxies, selected)| ProxyGroupDto {
                tag,
                group_type,
                proxies,
                selected,
            })
    }

    fn arb_rule_dto() -> impl Strategy<Value = RuleDto> {
        (
            prop_oneof![
                "domain",
                "domain-suffix",
                "domain-keyword",
                "ip-cidr",
                "geoip",
                "match"
            ],
            "[a-z]{3,20}",
            "[a-z]{3,10}",
            any::<u64>(),
        )
            .prop_map(|(rule_type, payload, outbound, matched_count)| RuleDto {
                rule_type,
                payload,
                outbound,
                matched_count,
            })
    }

    fn arb_dns_config_dto() -> impl Strategy<Value = DnsConfigDto> {
        (
            any::<bool>(),
            "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}:[0-9]{1,5}",
            prop_oneof!["normal", "fake-ip"],
            proptest::collection::vec("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}", 1..3),
            proptest::collection::vec("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}", 0..2),
        )
            .prop_map(|(enable, listen, enhanced_mode, nameservers, fallback)| {
                DnsConfigDto {
                    enable,
                    listen,
                    enhanced_mode,
                    nameservers,
                    fallback,
                }
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// For any TrafficStatsDto, serializing to JSON and deserializing
        /// back produces an equivalent value.
        #[test]
        fn test_traffic_stats_dto_roundtrip(dto in arb_traffic_stats_dto()) {
            let json = nextjson::to_string(&dto).expect("Failed to serialize");
            let deserialized: TrafficStatsDto = nextjson::from_str(&json).expect("Failed to deserialize");

            prop_assert_eq!(dto.upload, deserialized.upload);
            prop_assert_eq!(dto.download, deserialized.download);
            prop_assert_eq!(dto.total_upload, deserialized.total_upload);
            prop_assert_eq!(dto.total_download, deserialized.total_download);
            prop_assert_eq!(dto.connection_count, deserialized.connection_count);
            prop_assert_eq!(dto.uptime_secs, deserialized.uptime_secs);
        }

        /// For any ConnectionDto, serializing to JSON and deserializing back
        /// produces an equivalent value.
        #[test]
        fn test_connection_dto_roundtrip(dto in arb_connection_dto()) {
            let json = nextjson::to_string(&dto).expect("Failed to serialize");
            let deserialized: ConnectionDto = nextjson::from_str(&json).expect("Failed to deserialize");

            prop_assert_eq!(dto.id, deserialized.id);
            prop_assert_eq!(dto.src_addr, deserialized.src_addr);
            prop_assert_eq!(dto.dst_addr, deserialized.dst_addr);
            prop_assert_eq!(dto.dst_domain, deserialized.dst_domain);
            prop_assert_eq!(dto.protocol, deserialized.protocol);
            prop_assert_eq!(dto.outbound, deserialized.outbound);
            prop_assert_eq!(dto.upload, deserialized.upload);
            prop_assert_eq!(dto.download, deserialized.download);
            prop_assert_eq!(dto.start_time, deserialized.start_time);
            prop_assert_eq!(dto.rule, deserialized.rule);
        }

        /// For any ProxyInfoDto, serializing to JSON and deserializing back
        /// produces an equivalent value.
        #[test]
        fn test_proxy_info_dto_roundtrip(dto in arb_proxy_info_dto()) {
            let json = nextjson::to_string(&dto).expect("Failed to serialize");
            let deserialized: ProxyInfoDto = nextjson::from_str(&json).expect("Failed to deserialize");

            prop_assert_eq!(dto.tag, deserialized.tag);
            prop_assert_eq!(dto.protocol_type, deserialized.protocol_type);
            prop_assert_eq!(dto.server, deserialized.server);
            prop_assert_eq!(dto.port, deserialized.port);
            prop_assert_eq!(dto.latency_ms, deserialized.latency_ms);
            prop_assert_eq!(dto.alive, deserialized.alive);
        }

        /// For any ProxyGroupDto, serializing to JSON and deserializing back
        /// produces an equivalent value.
        #[test]
        fn test_proxy_group_dto_roundtrip(dto in arb_proxy_group_dto()) {
            let json = nextjson::to_string(&dto).expect("Failed to serialize");
            let deserialized: ProxyGroupDto = nextjson::from_str(&json).expect("Failed to deserialize");

            prop_assert_eq!(dto.tag, deserialized.tag);
            prop_assert_eq!(dto.group_type, deserialized.group_type);
            prop_assert_eq!(dto.proxies, deserialized.proxies);
            prop_assert_eq!(dto.selected, deserialized.selected);
        }

        /// For any RuleDto, serializing to JSON and deserializing back
        /// produces an equivalent value.
        #[test]
        fn test_rule_dto_roundtrip(dto in arb_rule_dto()) {
            let json = nextjson::to_string(&dto).expect("Failed to serialize");
            let deserialized: RuleDto = nextjson::from_str(&json).expect("Failed to deserialize");

            prop_assert_eq!(dto.rule_type, deserialized.rule_type);
            prop_assert_eq!(dto.payload, deserialized.payload);
            prop_assert_eq!(dto.outbound, deserialized.outbound);
            prop_assert_eq!(dto.matched_count, deserialized.matched_count);
        }

        /// For any DnsConfigDto, serializing to JSON and deserializing back
        /// produces an equivalent value.
        #[test]
        fn test_dns_config_dto_roundtrip(dto in arb_dns_config_dto()) {
            let json = nextjson::to_string(&dto).expect("Failed to serialize");
            let deserialized: DnsConfigDto = nextjson::from_str(&json).expect("Failed to deserialize");

            prop_assert_eq!(dto.enable, deserialized.enable);
            prop_assert_eq!(dto.listen, deserialized.listen);
            prop_assert_eq!(dto.enhanced_mode, deserialized.enhanced_mode);
            prop_assert_eq!(dto.nameservers, deserialized.nameservers);
            prop_assert_eq!(dto.fallback, deserialized.fallback);
        }
    }
}
