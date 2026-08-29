//! Shared RPC dispatch layer for the Corduit engine.
//!
//! This module is the **single source of truth** for the remote-control
//! surface of the engine. Every transport calls [`dispatch`]:
//!
//! * the hand-written C ABI (`crate::ffi`) — used by Flutter / Kotlin / Swift
//!   native hosts;
//! * the localhost HTTP + WebSocket JSON-RPC server (`crate::rpc::server`) —
//!   used by web dashboards and any language with an HTTP stack.
//!
//! The wire contract is intentionally tiny and format-neutral:
//!
//! * request: a JSON object `{ "method": "<name>", "params": { ... } }`;
//! * success: `{ "code": 0, "data": <value> }`;
//! * error:   `{ "code": 1, "error": "<message>" }`.
//!
//! All argument types are validated at the boundary (`Args`), so the engine's
//! interior code always sees typed, already-checked values. `nextjson` is the
//! only serialization technology involved (JSON for humans, `rustbinary` for
//! the compact binary FFI channel).

use nextjson::NsonSerialize;

use crate::api;

/// The HTTP/WebSocket JSON-RPC server transport.
pub mod server;

// ---------------------------------------------------------------------------
// Argument decoding
// ---------------------------------------------------------------------------

/// Named-argument view over a `nextjson::Value` object.
struct Args<'a>(&'a nextjson::Value);

impl<'a> Args<'a> {
    fn get(&self, key: &str) -> Result<&'a nextjson::Value, String> {
        self.0
            .get(key)
            .ok_or_else(|| format!("missing argument '{key}'"))
    }

    fn string(&self, key: &str) -> Result<String, String> {
        self.get(key)?
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("argument '{key}' must be a string"))
    }

    fn opt_string(&self, key: &str) -> Result<Option<String>, String> {
        match self.0.get(key) {
            None => Ok(None),
            Some(v) if v.is_null() => Ok(None),
            Some(v) => v
                .as_str()
                .map(str::to_string)
                .map(Some)
                .ok_or_else(|| format!("argument '{key}' must be a string")),
        }
    }

    fn u16(&self, key: &str) -> Result<u16, String> {
        self.get(key)?
            .as_u64()
            .and_then(|v| u16::try_from(v).ok())
            .ok_or_else(|| format!("argument '{key}' must be an integer in u16 range"))
    }

    fn u32(&self, key: &str) -> Result<u32, String> {
        self.get(key)?
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| format!("argument '{key}' must be an integer in u32 range"))
    }

    fn opt_u32(&self, key: &str) -> Result<Option<u32>, String> {
        match self.0.get(key) {
            None => Ok(None),
            Some(v) if v.is_null() => Ok(None),
            Some(v) => v
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .map(Some)
                .ok_or_else(|| format!("argument '{key}' must be an integer in u32 range")),
        }
    }

    fn u64(&self, key: &str) -> Result<u64, String> {
        self.get(key)?
            .as_u64()
            .ok_or_else(|| format!("argument '{key}' must be an unsigned integer"))
    }

    fn i32(&self, key: &str) -> Result<i32, String> {
        self.get(key)?
            .as_i64()
            .and_then(|v| i32::try_from(v).ok())
            .ok_or_else(|| format!("argument '{key}' must be an integer in i32 range"))
    }

    fn bool(&self, key: &str) -> Result<bool, String> {
        self.get(key)?
            .as_bool()
            .ok_or_else(|| format!("argument '{key}' must be a boolean"))
    }

    /// Decode `Vec<(server, port)>` for the batch latency API.
    fn proxies(&self, key: &str) -> Result<Vec<(String, u16)>, String> {
        let array = self
            .get(key)?
            .as_array()
            .ok_or_else(|| format!("argument '{key}' must be an array of objects"))?;
        let mut out = Vec::with_capacity(array.len());
        for item in array {
            let server = item
                .get("server")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "proxy entry missing string 'server'".to_string())?
                .to_string();
            let port = item
                .get("port")
                .and_then(|v| v.as_u64())
                .and_then(|v| u16::try_from(v).ok())
                .ok_or_else(|| format!("proxy '{server}' missing 'port' in u16 range"))?;
            out.push((server, port));
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Result plumbing
// ---------------------------------------------------------------------------

/// Result of a dispatch call: the encoded value or a human-readable error.
pub type HandlerResult = Result<nextjson::Value, String>;

/// Fold a typed synchronous API call into a `nextjson::Value`.
fn call<T, E>(res: Result<T, E>) -> HandlerResult
where
    T: NsonSerialize,
    E: std::fmt::Display,
{
    match res {
        Ok(value) => nextjson::to_value(&value).map_err(|e| format!("response encode failed: {e}")),
        Err(e) => Err(format!("{e}")),
    }
}

/// Encode an already-computed value.
fn value<T: NsonSerialize>(v: &T) -> HandlerResult {
    nextjson::to_value(v).map_err(|e| format!("response encode failed: {e}"))
}

fn ok_null() -> HandlerResult {
    Ok(nextjson::Value::Null)
}

// ---------------------------------------------------------------------------
// Typed dispatch table (single source of truth for every method)
// ---------------------------------------------------------------------------

/// Invoke a named API method with a JSON object of named arguments.
///
/// This is the only entry point every transport (FFI, HTTP, WebSocket) calls.
/// Unknown methods and malformed arguments are reported as errors, never
/// panics.
pub fn dispatch(method: &str, args: &nextjson::Value) -> HandlerResult {
    let args = Args(args);
    match method {
        // ---- lifecycle ----
        "init_app" => {
            api::init_app();
            ok_null()
        }

        // ---- proxy control (YAML) ----
        "start_proxy_from_yaml" => {
            let yaml = args.string("yaml_config")?;
            call(api::start_proxy_from_yaml(yaml))
        }
        "start_proxy_from_file" => {
            let path = args.string("config_path")?;
            call(api::start_proxy_from_file(path))
        }
        "stop_proxy" => call(api::stop_proxy()),
        "is_proxy_running" => call(api::is_proxy_running()),
        "reload_config_from_yaml" => {
            let yaml = args.string("yaml_config")?;
            call(api::reload_config_from_yaml(yaml))
        }
        "reload_config_from_file" => {
            let path = args.string("config_path")?;
            call(api::reload_config_from_file(path))
        }

        // ---- dashboard / DTOs ----
        "get_traffic_stats_dto" => call(api::get_traffic_stats_dto()),
        "get_connections_dto" => call(api::get_connections_dto()),
        "close_connection_by_id" => {
            let id = args.string("id")?;
            call(api::close_connection_by_id(id))
        }
        "close_all_connections_dto" => call(api::close_all_connections_dto()),
        "get_proxies" => call(api::get_proxies()),
        "get_proxy_groups" => call(api::get_proxy_groups()),
        "select_proxy" => {
            let group = args.string("group_tag")?;
            let proxy = args.string("proxy_tag")?;
            call(api::select_proxy(group, proxy))
        }
        "test_proxy_latency_dto" => {
            let tag = args.string("tag")?;
            let url = args.string("test_url")?;
            let timeout = args.u64("timeout_ms")?;
            call(api::test_proxy_latency_dto(tag, url, timeout))
        }
        "test_all_proxies_latency" => {
            let url = args.string("test_url")?;
            let timeout = args.u64("timeout_ms")?;
            call(api::test_all_proxies_latency(url, timeout))
        }
        "get_rules" => call(api::get_rules()),
        "get_dns_config" => call(api::get_dns_config()),
        "set_proxy_mode" => {
            let mode = args.i32("mode")?;
            call(api::set_proxy_mode(mode))
        }
        "get_proxy_mode" => call(api::get_proxy_mode()),

        // ---- TUN / VPN (legacy Windows entry points) ----
        "start_tun_mode" => {
            let name = args.string("tun_name")?;
            let address = args.string("tun_address")?;
            let netmask = args.string("tun_netmask")?;
            call(api::start_tun_mode(name, address, netmask))
        }
        "stop_tun_mode" => call(api::stop_tun_mode()),

        // ---- modern engine API ----
        "initialize_corduit" => {
            let config = args.string("config_json")?;
            call(api::initialize_corduit(config))
        }
        "start_corduit" => call(api::start_corduit()),
        "stop_corduit" => call(api::stop_corduit()),
        "reload_corduit" => {
            let config = args.string("config_json")?;
            call(api::reload_corduit(config))
        }
        "get_corduit_status" => call(api::get_corduit_status()),
        "get_traffic_stats" => call(api::get_traffic_stats()),
        "test_config" => {
            let config = args.string("config_json")?;
            call(api::test_config(config))
        }
        "get_connections" => call(api::get_connections()),
        "close_connection" => {
            let id = args.string("connection_id")?;
            call(api::close_connection(id))
        }
        "get_logs" => {
            let lines = args.opt_u32("lines")?;
            call(api::get_logs(lines))
        }
        "set_log_level" => {
            let level = args.string("level")?;
            call(api::set_log_level(level))
        }
        "get_system_info" => call(api::get_system_info()),
        "get_version" => value(&api::get_version()),
        "get_build_info" => value(&api::get_build_info()),

        // ---- latency testing ----
        "test_proxy_latency" => {
            let server = args.string("server")?;
            let port = args.u16("port")?;
            let timeout = args.u32("timeout_ms")?;
            call(api::test_proxy_latency(server, port, timeout))
        }
        "test_outbound_latency" => {
            let name = args.string("outbound_name")?;
            let timeout = args.u32("timeout_ms")?;
            call(api::test_outbound_latency(name, timeout))
        }
        "test_tcp_connectivity" => {
            let server = args.string("server")?;
            let port = args.u16("port")?;
            let timeout = args.u32("timeout_ms")?;
            call(api::test_tcp_connectivity(server, port, timeout))
        }
        "test_shadowsocks_latency" => {
            let server = args.string("server")?;
            let port = args.u16("port")?;
            let password = args.string("password")?;
            let cipher = args.string("cipher")?;
            let timeout = args.u32("timeout_ms")?;
            call(api::test_shadowsocks_latency(
                server, port, password, cipher, timeout,
            ))
        }
        "test_proxies_latency" => {
            let proxies = args.proxies("proxies")?;
            let timeout = args.u32("timeout_ms")?;
            call(api::test_proxies_latency(proxies, timeout))
        }

        // ---- proxy group selection ----
        "select_proxy_in_group" => {
            let group = args.string("group_name")?;
            let proxy = args.string("proxy_name")?;
            call(api::select_proxy_in_group(group, proxy))
        }
        "get_selected_proxy_in_group" => {
            let group = args.string("group_name")?;
            call(api::get_selected_proxy_in_group(group))
        }

        // ---- connection tracking ----
        "get_active_connections" => call(api::get_active_connections()),
        "close_active_connection" => {
            let id = args.string("connection_id")?;
            call(api::close_active_connection(id))
        }
        "close_all_connections" => call(api::close_all_connections()),
        "get_connection_stats" => call(api::get_connection_stats()),

        // ---- wintun / TUN status ----
        "is_wintun_available" => value(&api::is_wintun_available()),
        "get_wintun_dll_path" => value(&api::get_wintun_dll_path()),
        "ensure_wintun_dll" => call(api::ensure_wintun_dll()),
        "enable_tun_mode" => call(api::enable_tun_mode()),
        "enable_tun_mode_with_mode" => {
            let mode = args.string("mode")?;
            call(api::enable_tun_mode_with_mode(mode))
        }
        "disable_tun_mode" => call(api::disable_tun_mode()),
        "get_tun_status" => call(api::get_tun_status()),
        "set_windows_proxy_mode" => {
            let mode = args.string("mode")?;
            call(api::set_windows_proxy_mode(mode))
        }
        "get_windows_proxy_mode_str" => value(&api::get_windows_proxy_mode_str()),
        "get_windows_tun_stats" => call(api::get_windows_tun_stats()),
        "enable_uwp_loopback" => call(api::enable_uwp_loopback()),
        "open_uwp_loopback_utility" => call(api::open_uwp_loopback_utility()),

        // ---- Android ----
        "set_android_vpn_fd" => {
            let fd = args.i32("fd")?;
            api::set_android_vpn_fd(fd);
            ok_null()
        }
        "get_android_vpn_fd" => value(&api::get_android_vpn_fd()),
        "clear_android_vpn_fd" => {
            api::clear_android_vpn_fd();
            ok_null()
        }
        "set_android_proxy_mode" => {
            let mode = args.string("mode")?;
            api::set_android_proxy_mode(mode);
            ok_null()
        }
        "get_android_proxy_mode" => value(&api::get_android_proxy_mode()),
        "start_android_vpn" => call(api::start_android_vpn()),
        "stop_android_vpn" => call(api::stop_android_vpn()),

        // ---- iOS ----
        "set_ios_vpn_fd" => {
            let fd = args.i32("fd")?;
            api::set_ios_vpn_fd(fd);
            ok_null()
        }
        "get_ios_vpn_fd" => value(&api::get_ios_vpn_fd()),
        "clear_ios_vpn_fd" => {
            api::clear_ios_vpn_fd();
            ok_null()
        }

        // ---- VPN fd (Android, legacy) ----
        "set_vpn_fd" => {
            let fd = args.i32("fd")?;
            api::set_vpn_fd(fd);
            ok_null()
        }
        "clear_vpn_fd" => {
            api::clear_vpn_fd();
            ok_null()
        }
        "set_protect_socket_callback_enabled" => {
            let enabled = args.bool("enabled")?;
            api::set_protect_socket_callback_enabled(enabled);
            ok_null()
        }

        // ---- local RPC server control (web dashboards) ----
        "start_rpc_server" => {
            let port = args.u16("port")?;
            let token = args.opt_string("token")?;
            call(api::start_rpc_server(port, token))
        }
        "stop_rpc_server" => call(api::stop_rpc_server()),
        "get_rpc_server_status" => call(api::get_rpc_server_status()),

        _ => Err(format!("unknown method '{method}'")),
    }
}

// ---------------------------------------------------------------------------
// Bridge metadata
// ---------------------------------------------------------------------------

/// Bridge ABI version. Bump on any breaking change to the dispatch surface
/// or the wire schemas of `corduit_call` / `corduit_call_binary` / the RPC
/// server.
pub const CORDUIT_API_VERSION: &str = "0.2.0";

/// Every method accepted by [`dispatch`]. Cross-language hosts use this to
/// validate their bindings against the running library instead of hard-coding
/// method lists.
pub const CORDUIT_METHODS: &[&str] = &[
    // lifecycle
    "init_app",
    // proxy control (YAML)
    "start_proxy_from_yaml",
    "start_proxy_from_file",
    "stop_proxy",
    "is_proxy_running",
    "reload_config_from_yaml",
    "reload_config_from_file",
    // dashboard / DTOs
    "get_traffic_stats_dto",
    "get_connections_dto",
    "close_connection_by_id",
    "close_all_connections_dto",
    "get_proxies",
    "get_proxy_groups",
    "select_proxy",
    "test_proxy_latency_dto",
    "test_all_proxies_latency",
    "get_rules",
    "get_dns_config",
    "set_proxy_mode",
    "get_proxy_mode",
    // TUN / VPN
    "start_tun_mode",
    "stop_tun_mode",
    // modern engine API
    "initialize_corduit",
    "start_corduit",
    "stop_corduit",
    "reload_corduit",
    "get_corduit_status",
    "get_traffic_stats",
    "test_config",
    "get_connections",
    "close_connection",
    "get_logs",
    "set_log_level",
    "get_system_info",
    "get_version",
    "get_build_info",
    // latency testing
    "test_proxy_latency",
    "test_outbound_latency",
    "test_tcp_connectivity",
    "test_shadowsocks_latency",
    "test_proxies_latency",
    // proxy group selection
    "select_proxy_in_group",
    "get_selected_proxy_in_group",
    // connection tracking
    "get_active_connections",
    "close_active_connection",
    "close_all_connections",
    "get_connection_stats",
    // wintun / TUN status
    "is_wintun_available",
    "get_wintun_dll_path",
    "ensure_wintun_dll",
    "enable_tun_mode",
    "enable_tun_mode_with_mode",
    "disable_tun_mode",
    "get_tun_status",
    "set_windows_proxy_mode",
    "get_windows_proxy_mode_str",
    "get_windows_tun_stats",
    "enable_uwp_loopback",
    "open_uwp_loopback_utility",
    // android
    "set_android_vpn_fd",
    "get_android_vpn_fd",
    "clear_android_vpn_fd",
    "set_android_proxy_mode",
    "get_android_proxy_mode",
    "start_android_vpn",
    "stop_android_vpn",
    // vpn fd (legacy)
    "set_vpn_fd",
    "clear_vpn_fd",
    "set_protect_socket_callback_enabled",
    // local RPC server control
    "start_rpc_server",
    "stop_rpc_server",
    "get_rpc_server_status",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_rejects_unknown_method() {
        let value = nextjson::Value::Null;
        let result = dispatch("no_such_method", &value);
        assert!(result.is_err());
    }

    #[test]
    fn args_parse_named_arguments() {
        let value: nextjson::Value = nextjson::from_str(
            r#"{"tag":"proxy-1","test_url":"http://example.com","timeout_ms":1000}"#,
        )
        .unwrap();
        let args = Args(&value);
        assert_eq!(args.string("tag").unwrap(), "proxy-1");
        assert_eq!(args.u64("timeout_ms").unwrap(), 1000);
        assert!(args.string("missing").is_err());
        assert!(args.u16("tag").is_err());
    }

    #[test]
    fn args_parse_proxies_array() {
        let value: nextjson::Value = nextjson::from_str(
            r#"{"proxies":[{"server":"a.com","port":443},{"server":"b.com","port":80}]}"#,
        )
        .unwrap();
        let args = Args(&value);
        let proxies = args.proxies("proxies").unwrap();
        assert_eq!(proxies, vec![("a.com".into(), 443), ("b.com".into(), 80)]);
    }

    #[test]
    fn json_roundtrip_of_dto() {
        let dto = crate::TrafficStatsDto::new();
        let json = nextjson::to_string(&dto).expect("encode");
        let back: crate::TrafficStatsDto = nextjson::from_str(&json).expect("decode");
        assert_eq!(back.upload, dto.upload);
    }

    #[test]
    fn binary_roundtrip_via_rustbinary() {
        let value: nextjson::Value = nextjson::from_str(r#"{"mode":1}"#).unwrap();
        let encoded = rustbinary::serialize(&value).expect("binary encode");
        let decoded: nextjson::Value = rustbinary::deserialize(&encoded).expect("binary decode");
        assert_eq!(decoded.get("mode").and_then(|v| v.as_i64()), Some(1));
    }

    #[test]
    fn every_declared_method_is_dispatched() {
        // Ensure platform hooks (incl. the legacy crypto-provider no-op) are ready
        // before dispatching methods that build HTTP clients.
        api::init_app();

        let value = nextjson::Value::Null;
        for method in CORDUIT_METHODS {
            let result = dispatch(method, &value);
            if let Err(e) = result {
                assert!(
                    !e.starts_with("unknown method"),
                    "declared method '{method}' is missing from dispatch: {e}"
                );
            }
        }
    }

    #[test]
    fn api_version_is_semver_like() {
        assert!(
            CORDUIT_API_VERSION.split('.').count() >= 2,
            "expected semver-ish string"
        );
    }
}
