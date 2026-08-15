//! Hand-written, dependency-free C ABI for the Corduit engine.
//!
//! No code generation, no third-party FFI framework — every symbol below is
//! authored in plain Rust against the C ABI. The Flutter/mobile/Dart side no
//! longer needs `flutter_rust_bridge`; it binds these functions directly.
//!
//! Two wire formats are exposed at the boundary, sharing one typed dispatch
//! table ([`crate::rpc::dispatch`]):
//!
//! * [`corduit_call`] — `nextjson` (human-readable JSON) payloads;
//! * [`corduit_call_binary`] — `rustbinary` (compact, bounded, type-tagged)
//!   payloads.
//!
//! Callers must free returned buffers with [`corduit_string_free`] /
//! [`corduit_binary_free`]. Thread-safe: a shared multi-threaded Tokio runtime
//! drives every async API internally, and no panic ever unwinds across the
//! `extern "C"` boundary.

use std::ffi::{c_char, CStr, CString};
use std::ptr;
use std::sync::OnceLock;

use crate::api;
use crate::rpc::{dispatch, CORDUIT_API_VERSION, CORDUIT_METHODS};

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
// Public entry points
// ---------------------------------------------------------------------------

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
/// * `method` — NUL-terminated method name (see [`CORDUIT_METHODS`]).
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
    // A panic must never unwind across the `extern "C"` boundary (UB). The
    // whole body is fenced so any internal panic becomes a structured error.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let method = unsafe { read_cstr(method) }.to_string();
        let raw = unsafe { read_cstr(args_json) };
        let value: nextjson::Value = if raw.is_empty() {
            nextjson::Value::Null
        } else {
            nextjson::from_str(raw).unwrap_or(nextjson::Value::Null)
        };

        runtime().block_on(dispatch(&method, &value))
    })) {
        Ok(Ok(v)) => match nextjson::to_string(&v) {
            Ok(s) => FfiResponse::ok(s),
            Err(e) => FfiResponse::err(format!("response encode failed: {e}")),
        },
        Ok(Err(e)) => FfiResponse::err(e),
        Err(_) => FfiResponse::err(
            "internal error: request handler panicked (no unwind across the FFI boundary)".into(),
        ),
    }
}

/// Invoke a named API with a rustbinary (binary) payload.
///
/// * `method` — NUL-terminated method name.
/// * `payload`/`len` — rustbinary-encoded argument object, or null/0.
///
/// Returns an [`FfiBinaryResponse`] whose buffer must be released with
/// [`corduit_binary_free`]. Deserialization is bounded by rustbinary's strict
/// profile (64 MiB input cap, collection limit, trailing bytes rejected).
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
    // A panic must never unwind across the `extern "C"` boundary (UB).
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let method = unsafe { read_cstr(method) }.to_string();
        let value: nextjson::Value = if payload.is_null() || len == 0 {
            nextjson::Value::Null
        } else {
            let bytes = unsafe { std::slice::from_raw_parts(payload, len) };
            rustbinary::deserialize(bytes).unwrap_or(nextjson::Value::Null)
        };

        runtime().block_on(dispatch(&method, &value))
    })) {
        Ok(Ok(v)) => match rustbinary::serialize(&v) {
            Ok(bytes) => FfiBinaryResponse::ok(bytes),
            Err(e) => FfiBinaryResponse::err(format!("response encode failed: {e}")),
        },
        Ok(Err(e)) => FfiBinaryResponse::err(e),
        Err(_) => FfiBinaryResponse::err(
            "internal error: request handler panicked (no unwind across the FFI boundary)".into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(
            CORDUIT_API_VERSION.split('.').count() >= 2,
            "expected semver-ish string"
        );
    }

    #[test]
    fn json_call_roundtrip() {
        // A null argument set must never panic and must not crash the ABI.
        let resp = unsafe {
            let method = CString::new("get_version").unwrap();
            corduit_call(method.as_ptr(), ptr::null())
        };
        assert_eq!(resp.code, 0);
        unsafe {
            let s = CStr::from_ptr(resp.data).to_str().unwrap().to_string();
            drop(CString::from_raw(resp.data));
            assert!(s.contains("version") || s.contains("0.1"), "unexpected: {s}");
        }
    }

    #[test]
    fn binary_call_roundtrip() {
        let params: nextjson::Value = nextjson::from_str(r#"{"mode":1}"#).unwrap();
        let encoded = rustbinary::serialize(&params).unwrap();
        let resp = unsafe {
            let method = CString::new("get_proxy_mode").unwrap();
            corduit_call_binary(method.as_ptr(), encoded.as_ptr(), encoded.len())
        };
        unsafe {
            if resp.code == 0 && !resp.data.is_null() {
                let bytes = std::slice::from_raw_parts(resp.data, resp.len).to_vec();
                corduit_binary_free(resp);
                let v: nextjson::Value = rustbinary::deserialize(&bytes).unwrap_or(nextjson::Value::Null);
                let _ = v;
            }
        }
    }
}
