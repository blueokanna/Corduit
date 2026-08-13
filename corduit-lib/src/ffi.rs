//! Hand-written, dependency-free C ABI for the Corduit engine.
//!
//! No code generation, no third-party FFI framework — every symbol below is
//! authored in plain Rust against the C ABI. The Flutter/mobile/Dart side no
//! longer needs `flutter_rust_bridge`; it binds these functions directly.
//!
//! Two wire formats are exposed at the boundary, sharing one typed dispatch
//! table:
//!
//! * [`corduit_call`] — `nextjson` (human-readable JSON) payloads;
//! * [`corduit_call_binary`] — `rustbinary` (compact, bounded, type-tagged)
//!   payloads.
//!
//! Callers must free returned buffers with [`corduit_string_free`] /
//! [`corduit_binary_free`]. Thread-safe: a shared multi-threaded Tokio runtime
//! drives every async API internally.

use std::ffi::{CStr, CString, c_char};
use std::future::Future;
use std::ptr;
use std::sync::OnceLock;

use nextjson::NsonSerialize;

use crate::api as api;

// ---------------------------------------------------------------------------
// Shared async runtime
// ---------------------------------------------------------------------------

/// Lazily-initialized multi-threaded runtime used by every async FFI method.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("corduit-ffi")
            .build()
            .expect("failed to build the Corduit FFI tokio runtime")
    })
}

// ---------------------------------------------------------------------------
// C-compatible response types
// ---------------------------------------------------------------------------

/// Result of a [`corduit_call`] invocation.
#[repr(C)]
pub struct FfiResponse {
    /// `0` on success, non-zero on error.
    pub code: i32,
    /// UTF-8 payload (nextjson JSON). Free with [`corduit_string_free`].
    pub data: *mut c_char,
}

/// Result of a [`corduit_call_binary`] invocation.
#[repr(C)]
pub struct FfiBinaryResponse {
    /// `0` on success, non-zero on error.
    pub code: i32,
    /// rustbinary payload. Free with [`corduit_binary_free`].
    pub data: *mut u8,
    /// Number of valid bytes in `data`.
    pub len: usize,
}

impl FfiResponse {
    fn ok(s: String) -> Self {
        Self {
            code: 0,
            data: into_cstring(s),
        }
    }

    fn err(s: String) -> Self {
        Self {
            code: 1,
            data: into_cstring(s),
        }
    }
}

impl FfiBinaryResponse {
    fn ok(bytes: Vec<u8>) -> Self {
        let mut bytes = bytes;
        let len = bytes.len();
        let data = if bytes.is_empty() {
            ptr::null_mut()
        } else {
            let p = bytes.as_mut_ptr();
            std::mem::forget(bytes); // ownership transferred to the caller
            p
        };
        Self { code: 0, data, len }
    }

    fn err(s: String) -> Self {
        Self::ok(s.into_bytes())
    }
}

fn into_cstring(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// SAFETY: `ptr` must be a valid NUL-terminated string (or null).
unsafe fn read_cstr<'a>(ptr: *const c_char) -> &'a str {
    if ptr.is_null() {
        return "";
    }
    CStr::from_ptr(ptr).to_str().unwrap_or("")
}

/// Free a string returned by [`corduit_call`].
///
/// # Safety
/// `ptr` must come from a previous successful [`corduit_call`] (or be null).
#[no_mangle]
pub unsafe extern "C" fn corduit_string_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

/// Free a binary buffer returned by [`corduit_call_binary`].
///
/// # Safety
/// `resp` must come from a previous [`corduit_call_binary`] call.
#[no_mangle]
pub unsafe extern "C" fn corduit_binary_free(resp: FfiBinaryResponse) {
    if !resp.data.is_null() && resp.len > 0 {
        drop(Vec::from_raw_parts(resp.data, resp.len, resp.len));
    }
}

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

type HandlerResult = Result<nextjson::Value, String>;

/// Await a typed async API call and fold it into a `nextjson::Value`.
async fn call<T, E>(fut: impl Future<Output = Result<T, E>>) -> HandlerResult
where
    T: NsonSerialize,
    E: std::fmt::Display,
{
    match fut.await {
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

async fn dispatch(method: &str, args: Args<'_>) -> HandlerResult {
    match method {
        // ---- lifecycle ----
        "init_app" => {
            api::init_app();
            ok_null()
        }

        // ---- proxy control (YAML) ----
        "start_proxy_from_yaml" => {
            let yaml = args.string("yaml_config")?;
            call(api::start_proxy_from_yaml(yaml)).await
        }
        "start_proxy_from_file" => {
            let path = args.string("config_path")?;
            call(api::start_proxy_from_file(path)).await
        }
        "stop_proxy" => call(api::stop_proxy()).await,
        "is_proxy_running" => call(api::is_proxy_running()).await,
        "reload_config_from_yaml" => {
            let yaml = args.string("yaml_config")?;
            call(api::reload_config_from_yaml(yaml)).await
        }
        "reload_config_from_file" => {
            let path = args.string("config_path")?;
            call(api::reload_config_from_file(path)).await
        }

        // ---- dashboard / DTOs ----
        "get_traffic_stats_dto" => call(api::get_traffic_stats_dto()).await,
        "get_connections_dto" => call(api::get_connections_dto()).await,
        "close_connection_by_id" => {
            let id = args.string("id")?;
            call(api::close_connection_by_id(id)).await
        }
        "close_all_connections_dto" => call(api::close_all_connections_dto()).await,
        "get_proxies" => call(api::get_proxies()).await,
        "get_proxy_groups" => call(api::get_proxy_groups()).await,
        "select_proxy" => {
            let group = args.string("group_tag")?;
            let proxy = args.string("proxy_tag")?;
            call(api::select_proxy(group, proxy)).await
        }
        "test_proxy_latency_dto" => {
            let tag = args.string("tag")?;
            let url = args.string("test_url")?;
            let timeout = args.u64("timeout_ms")?;
            call(api::test_proxy_latency_dto(tag, url, timeout)).await
        }
        "test_all_proxies_latency" => {
            let url = args.string("test_url")?;
            let timeout = args.u64("timeout_ms")?;
            call(api::test_all_proxies_latency(url, timeout)).await
        }
        "get_rules" => call(api::get_rules()).await,
        "get_dns_config" => call(api::get_dns_config()).await,
        "set_proxy_mode" => {
            let mode = args.i32("mode")?;
            call(api::set_proxy_mode(mode)).await
        }
        "get_proxy_mode" => call(api::get_proxy_mode()).await,

        // ---- TUN / VPN (legacy Windows entry points) ----
        "start_tun_mode" => {
            let name = args.string("tun_name")?;
            let address = args.string("tun_address")?;
            let netmask = args.string("tun_netmask")?;
            call(api::start_tun_mode(name, address, netmask)).await
        }
        "stop_tun_mode" => call(api::stop_tun_mode()).await,

        // ---- modern engine API ----
        "initialize_corduit" => {
            let config = args.string("config_json")?;
            call(api::initialize_corduit(config)).await
        }
        "start_corduit" => call(api::start_corduit()).await,
        "stop_corduit" => call(api::stop_corduit()).await,
        "reload_corduit" => {
            let config = args.string("config_json")?;
            call(api::reload_corduit(config)).await
        }
        "get_corduit_status" => call(api::get_corduit_status()).await,
        "get_traffic_stats" => call(api::get_traffic_stats()).await,
        "test_config" => {
            let config = args.string("config_json")?;
            call(api::test_config(config)).await
        }
        "get_connections" => call(api::get_connections()).await,
        "close_connection" => {
            let id = args.string("connection_id")?;
            call(api::close_connection(id)).await
        }
        "get_logs" => {
            let lines = args.opt_u32("lines")?;
            call(api::get_logs(lines)).await
        }
        "set_log_level" => {
            let level = args.string("level")?;
            call(api::set_log_level(level)).await
        }
        "get_system_info" => call(api::get_system_info()).await,
        "get_version" => value(&api::get_version()),
        "get_build_info" => value(&api::get_build_info()),

        // ---- latency testing ----
        "test_proxy_latency" => {
            let server = args.string("server")?;
            let port = args.u16("port")?;
            let timeout = args.u32("timeout_ms")?;
            call(api::test_proxy_latency(server, port, timeout)).await
        }
        "test_outbound_latency" => {
            let name = args.string("outbound_name")?;
            let timeout = args.u32("timeout_ms")?;
            call(api::test_outbound_latency(name, timeout)).await
        }
        "test_tcp_connectivity" => {
            let server = args.string("server")?;
            let port = args.u16("port")?;
            let timeout = args.u32("timeout_ms")?;
            call(api::test_tcp_connectivity(server, port, timeout)).await
        }
        "test_shadowsocks_latency" => {
            let server = args.string("server")?;
            let port = args.u16("port")?;
            let password = args.string("password")?;
            let cipher = args.string("cipher")?;
            let timeout = args.u32("timeout_ms")?;
            call(api::test_shadowsocks_latency(server, port, password, cipher, timeout)).await
        }
        "test_proxies_latency" => {
            let proxies = args.proxies("proxies")?;
            let timeout = args.u32("timeout_ms")?;
            call(api::test_proxies_latency(proxies, timeout)).await
        }

        // ---- proxy group selection ----
        "select_proxy_in_group" => {
            let group = args.string("group_name")?;
            let proxy = args.string("proxy_name")?;
            call(api::select_proxy_in_group(group, proxy)).await
        }
        "get_selected_proxy_in_group" => {
            let group = args.string("group_name")?;
            call(api::get_selected_proxy_in_group(group)).await
        }

        // ---- connection tracking ----
        "get_active_connections" => call(api::get_active_connections()).await,
        "close_active_connection" => {
            let id = args.string("connection_id")?;
            call(api::close_active_connection(id)).await
        }
        "close_all_connections" => call(api::close_all_connections()).await,
        "get_connection_stats" => call(api::get_connection_stats()).await,

        // ---- wintun / TUN status ----
        "is_wintun_available" => value(&api::is_wintun_available()),
        "get_wintun_dll_path" => value(&api::get_wintun_dll_path()),
        "ensure_wintun_dll" => call(api::ensure_wintun_dll()).await,
        "enable_tun_mode" => call(api::enable_tun_mode()).await,
        "enable_tun_mode_with_mode" => {
            let mode = args.string("mode")?;
            call(api::enable_tun_mode_with_mode(mode)).await
        }
        "disable_tun_mode" => call(api::disable_tun_mode()).await,
        "get_tun_status" => call(api::get_tun_status()).await,
        "set_windows_proxy_mode" => {
            let mode = args.string("mode")?;
            call(async move { api::set_windows_proxy_mode(mode) }).await
        }
        "get_windows_proxy_mode_str" => value(&api::get_windows_proxy_mode_str()),
        "get_windows_tun_stats" => {
            call(async move { api::get_windows_tun_stats() }).await
        }
        "enable_uwp_loopback" => call(api::enable_uwp_loopback()).await,
        "open_uwp_loopback_utility" => call(api::open_uwp_loopback_utility()).await,

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
        "start_android_vpn" => call(api::start_android_vpn()).await,
        "stop_android_vpn" => call(api::stop_android_vpn()).await,

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

        _ => Err(format!("unknown method '{method}'")),
    }
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Bridge ABI version. Bump on any breaking change to `corduit_call` /
/// `corduit_call_binary` semantics or payload schemas.
pub const CORDUIT_API_VERSION: &str = "0.1.0";

/// Every method accepted by [`dispatch`]. Cross-language hosts use
/// [`corduit_methods`] to validate their bindings against the running library
/// instead of hard-coding method lists.
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
];

/// Initialize the bridge (logging, tracing, platform hooks).
#[no_mangle]
pub extern "C" fn corduit_init() {
    api::init_app();
}

/// Return the bridge ABI version as a C string (caller frees with
/// [`corduit_string_free`]).
#[no_mangle]
pub extern "C" fn corduit_api_version() -> *mut c_char {
    into_cstring(CORDUIT_API_VERSION.to_string())
}

/// Return the list of supported `corduit_call` methods as a JSON array string
/// (caller frees with [`corduit_string_free`]).
#[no_mangle]
pub extern "C" fn corduit_methods() -> *mut c_char {
    let json = nextjson::to_string(&nextjson::Value::Array(
        CORDUIT_METHODS
            .iter()
            .map(|m| nextjson::Value::String((*m).to_string()))
            .collect(),
    ))
    .unwrap_or_else(|_| "[]".to_string());
    into_cstring(json)
}

/// Invoke a named API with a nextjson (JSON) payload.
///
/// * `method` — NUL-terminated method name (see the `dispatch` table).
/// * `args_json` — NUL-terminated JSON object, or null for no arguments.
///
/// Returns an [`FfiResponse`] whose `data` must be released with
/// [`corduit_string_free`].
///
/// # Safety
///
/// Both pointers must be valid NUL-terminated C strings (or null) and stay
/// valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn corduit_call(
    method: *const c_char,
    args_json: *const c_char,
) -> FfiResponse {
    let method = unsafe { read_cstr(method) }.to_string();
    let raw = unsafe { read_cstr(args_json) };
    let value: nextjson::Value = if raw.is_empty() {
        nextjson::Value::Null
    } else {
        nextjson::from_str(raw).unwrap_or(nextjson::Value::Null)
    };

    let result = runtime().block_on(dispatch(&method, Args(&value)));
    match result {
        Ok(v) => match nextjson::to_string(&v) {
            Ok(s) => FfiResponse::ok(s),
            Err(e) => FfiResponse::err(format!("response encode failed: {e}")),
        },
        Err(e) => FfiResponse::err(e),
    }
}

/// Invoke a named API with a rustbinary (binary) payload.
///
/// * `method` — NUL-terminated method name.
/// * `payload`/`len` — rustbinary-encoded argument object, or null/0.
///
/// Returns an [`FfiBinaryResponse`] whose buffer must be released with
/// [`corduit_binary_free`].
///
/// # Safety
///
/// `method` must be a valid NUL-terminated C string (or null); `payload` must
/// point to `len` readable bytes (or be null when `len == 0`) and stay valid
/// for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn corduit_call_binary(
    method: *const c_char,
    payload: *const u8,
    len: usize,
) -> FfiBinaryResponse {
    let method = unsafe { read_cstr(method) }.to_string();
    let value: nextjson::Value = if payload.is_null() || len == 0 {
        nextjson::Value::Null
    } else {
        let bytes = unsafe { std::slice::from_raw_parts(payload, len) };
        rustbinary::deserialize(bytes).unwrap_or(nextjson::Value::Null)
    };

    let result = runtime().block_on(dispatch(&method, Args(&value)));
    match result {
        Ok(v) => match rustbinary::serialize(&v) {
            Ok(bytes) => FfiBinaryResponse::ok(bytes),
            Err(e) => FfiBinaryResponse::err(format!("response encode failed: {e}")),
        },
        Err(e) => FfiBinaryResponse::err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_rejects_unknown_method() {
        let value = nextjson::Value::Null;
        let result = runtime().block_on(dispatch("no_such_method", Args(&value)));
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
        // Ensure platform hooks (incl. the rustls crypto provider) are ready
        // before dispatching methods that build HTTP clients.
        api::init_app();

        let value = nextjson::Value::Null;
        for method in CORDUIT_METHODS {
            let result = runtime().block_on(dispatch(method, Args(&value)));
            if let Err(e) = result {
                assert!(
                    !e.starts_with("unknown method"),
                    "declared method '{method}' is missing from dispatch: {e}"
                );
            }
        }
    }

    #[test]
    fn methods_discovery_returns_valid_json_array() {
        let ptr = corduit_methods();
        assert!(!ptr.is_null());
        let json = unsafe {
            let s = CStr::from_ptr(ptr).to_str().unwrap().to_string();
            drop(CString::from_raw(ptr));
            s
        };
        let parsed: nextjson::Value = nextjson::from_str(&json).expect("valid JSON");
        let methods = parsed.as_array().expect("array of method names");
        assert_eq!(methods.len(), CORDUIT_METHODS.len());
        assert!(methods.iter().all(|m| m.as_str().is_some()));
    }

    #[test]
    fn api_version_is_semver_like() {
        let version = CORDUIT_API_VERSION;
        assert!(version.split('.').count() >= 2, "expected semver-ish string");
    }
}
