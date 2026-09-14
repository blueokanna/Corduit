//! Corduit Network Stack
//!
//! A userspace TCP/IP stack for TUN-based transparent proxying.
//!
//! This module provides:
//! - TUN device management (cross-platform, using wintun on Windows)
//! - the userspace TCP/IP stack ([`solidtcp`]): TCP connections and UDP
//!   sessions with NAT, fake-IP DNS interception, and per-connection
//!   proxying through the local SOCKS5 inbound
//! - the platform bridges ([`vpn`], `android_vpn`, `windows_vpn`) that move
//!   packets between a TUN descriptor and that stack
//! - routing helpers ([`route`], `windows_route`) for capturing traffic
//!
//! Packet parsing and construction use `smoltcp`'s wire types throughout;
//! there is no second, parallel stack implementation.
//!
//! # Platform Requirements
//!
//! ## Windows
//! Requires `wintun.dll` in the executable directory.
//! The library will attempt to download it automatically if not present.
//! Manual download: <https://www.wintun.net/>
//!
//! ## Linux
//! Requires CAP_NET_ADMIN capability or root privileges.
//!
//! ## macOS
//! Requires root privileges.
//!
//! ## Android
//! Requires VpnService permission.
//!
//! # Example
//!
//! ```rust,no_run
//! use corduit::netstack::TunPacketProcessor;
//!
//! fn run(packet: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
//!     // `tun_tx` receives the bytes to write back into the TUN device.
//!     let (tun_tx, tun_rx) = std::sync::mpsc::channel::<bytes::BytesMut>();
//!     let processor = TunPacketProcessor::new(17890, 1500, tun_tx);
//!
//!     // Read a packet from the TUN descriptor and hand it to the stack;
//!     // its connections leave through the local SOCKS5 inbound on 17890.
//!     processor.process_packet(packet)?;
//!     let _ = tun_rx;
//!     Ok(())
//! }
//! ```

#[cfg(target_os = "android")]
pub mod android_vpn;
pub mod error;
pub mod route;
pub mod solidtcp;
pub mod tun;
pub mod vpn;
#[cfg(windows)]
pub mod windows_route;
#[cfg(windows)]
pub mod windows_vpn;
#[cfg(windows)]
pub mod wintun_embed;

// Re-exports
pub use error::{NetStackError, Result};
pub use route::RouteManager;
pub use tun::{TunConfig, TunDevice};
pub use vpn::{TunPacketProcessor, TunTrafficStats};

// Re-export DNS types from corduit-dns crate
pub use crate::dns::{
    CacheStatistics,
    DnsCache,
    // Client
    DnsClient,
    DnsConfig,
    DnsError,
    // Core types
    DnsManager,
    DnsManagerState,
    DnsProtocol,
    DnsResolver,
    DnsServer,
    // DoH/DoT
    DohClient,
    DohClientConfig,
    DohMethod,
    DohResolver,
    DotClient,
    DotClientConfig,
    DotResolver,
    FakeIpEntry,
    // Fake-IP
    FakeIpPool,
    FallbackFilter,
    // Other
    HostsFile,
    RecordType,
    Result as DnsResult,
    // Config
    UpstreamConfig,
    UpstreamProtocol,
};

// Android-specific exports
#[cfg(target_os = "android")]
pub use tun::{
    clear_android_vpn_fd, get_android_proxy_mode, get_android_vpn_fd, set_android_proxy_mode,
    set_android_vpn_fd, ANDROID_PROXY_MODE, ANDROID_VPN_FD,
};

#[cfg(target_os = "ios")]
pub use tun::{clear_ios_vpn_fd, get_ios_vpn_fd, set_ios_vpn_fd, IOS_VPN_FD};

#[cfg(target_os = "android")]
pub use android_vpn::{AndroidVpnProcessor, VpnTrafficStats};

#[cfg(target_os = "android")]
pub use solidtcp::{
    clear_protect_callback, has_protect_callback, protect_socket, set_protect_callback,
};

// Windows-specific exports
#[cfg(windows)]
pub use windows_vpn::{
    get_windows_proxy_mode, set_windows_proxy_mode, WindowsVpnProcessor, WindowsVpnTrafficStats,
};

#[cfg(windows)]
pub use windows_route::{flush_dns_cache, set_tun_dns, WindowsRouteManager};

#[cfg(windows)]
pub fn check_wintun_available() -> bool {
    wintun_embed::is_wintun_available()
}

/// Check if wintun.dll is available (non-Windows)
#[cfg(not(windows))]
pub fn check_wintun_available() -> bool {
    true // Not needed on non-Windows platforms
}

/// Get the path where wintun.dll should be placed
#[cfg(windows)]
pub fn get_wintun_path() -> Option<std::path::PathBuf> {
    wintun_embed::get_wintun_dll_path().ok()
}

/// Get the path where wintun.dll should be placed (non-Windows)
#[cfg(not(windows))]
pub fn get_wintun_path() -> Option<std::path::PathBuf> {
    None
}

/// Ensure wintun.dll is available, downloading if necessary (Windows only)
#[cfg(windows)]
pub fn ensure_wintun() -> Result<std::path::PathBuf> {
    // First try to use existing or embedded
    if let Ok(path) = wintun_embed::ensure_wintun_available() {
        return Ok(path);
    }

    // Try to download
    wintun_embed::download_wintun_dll()
}

/// Ensure wintun.dll is available (non-Windows - always succeeds)
#[cfg(not(windows))]
pub fn ensure_wintun() -> Result<std::path::PathBuf> {
    Ok(std::path::PathBuf::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tun_config_default() {
        let config = TunConfig::default();
        assert_eq!(config.name, "Corduit");
        assert_eq!(config.address, std::net::Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(config.mtu, 1500);
    }
}
