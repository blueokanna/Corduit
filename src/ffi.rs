//! Hand-written, dependency-free C ABI for the Corduit engine.
//!
//! This optional C ABI shares the engine dispatcher with the RPC layer.
//! ArcadiaPlus also exposes its application API through flutter_rust_bridge;
//! these entry points do not replace that generated bridge.
//!
//! Two wire formats are exposed at the boundary, sharing one typed dispatch
//! table ([`crate::rpc::dispatch`]):
//!
//! * [`corduit_call`] — `nextjson` (human-readable JSON) payloads;
//! * [`corduit_call_binary`] — `rustbinary` (compact, bounded, type-tagged)
//!   payloads.
//!
//! Callers must free returned buffers with [`corduit_string_free`] /
//! [`corduit_binary_free`]. Thread-safe: every exported function runs the
//! engine synchronously on the calling thread, and no panic ever unwinds
//! across the `extern "C"` boundary.

use std::ffi::{c_char, CStr, CString};
use std::ptr;

use crate::api;
use crate::rpc::{dispatch, CORDUIT_API_VERSION, CORDUIT_METHODS};

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
    /// RustBinary on success; UTF-8 error text otherwise.
    /// Free with [`corduit_binary_free`].
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
    fn from_bytes(bytes: Vec<u8>, code: i32) -> Self {
        let boxed = bytes.into_boxed_slice();
        let len = boxed.len();
        if boxed.is_empty() {
            return Self {
                code,
                data: ptr::null_mut(),
                len: 0,
            };
        }
        // `into_boxed_slice` reallocates to exactly `len` bytes, so the
        // caller can rebuild a `Box<[u8]>` from `(data, len)` alone.
        let data = Box::into_raw(boxed) as *mut u8;
        Self { code, data, len }
    }

    fn ok(bytes: Vec<u8>) -> Self {
        Self::from_bytes(bytes, 0)
    }

    fn err(s: String) -> Self {
        Self::from_bytes(s.into_bytes(), 1)
    }
}

fn into_cstring(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

// Match the bounded RustBinary profile for both transports. Check the binary
// length before forming a Rust slice; catch_unwind cannot recover from UB.
const MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;
const MAX_METHOD_BYTES: usize = 128;

fn check_request_size(len: usize) -> Result<(), String> {
    if len > MAX_REQUEST_BYTES {
        return Err("request exceeds the 64 MiB input limit".into());
    }
    Ok(())
}

/// SAFETY: `ptr` must be a valid NUL-terminated string (or null).
unsafe fn read_cstr<'a>(ptr: *const c_char, limit: usize) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Ok("");
    }
    let bytes = CStr::from_ptr(ptr).to_bytes();
    if bytes.len() > limit {
        return Err("C string exceeds the input limit".into());
    }
    std::str::from_utf8(bytes).map_err(|_| "C string is not valid UTF-8".into())
}

/// Free a string returned by [`corduit_call`].
///
/// # Safety
/// `ptr` must be an unfreed string returned by this module (or be null).
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
        drop(Box::from_raw(ptr::slice_from_raw_parts_mut(
            resp.data, resp.len,
        )));
    }
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Initialize the bridge (logging, tracing, platform hooks).
#[no_mangle]
pub extern "C" fn corduit_init() {
    // Nothing here is expected to panic, but an unwind across `extern "C"`
    // would be UB; initialisation failure must not abort the host process.
    let _ = std::panic::catch_unwind(api::init_app);
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
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let method = unsafe { read_cstr(method, MAX_METHOD_BYTES) }?;
        let raw = unsafe { read_cstr(args_json, MAX_REQUEST_BYTES) }?;
        let value: nextjson::Value = if raw.is_empty() {
            nextjson::Value::Null
        } else {
            nextjson::from_str(raw).map_err(|e| format!("invalid JSON request: {e}"))?
        };

        dispatch(method, &value)
    }));

    match result {
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
/// `method` must be a valid NUL-terminated C string (or null). A non-null
/// `payload` must point to `len` readable bytes and stay valid for the call.
/// Null payloads with a nonzero length are rejected without dereferencing.
/// Invalid non-null pointers cannot be checked by this ABI.
#[no_mangle]
pub unsafe extern "C" fn corduit_call_binary(
    method: *const c_char,
    payload: *const u8,
    len: usize,
) -> FfiBinaryResponse {
    // A panic must never unwind across the `extern "C"` boundary (UB).
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let method = unsafe { read_cstr(method, MAX_METHOD_BYTES) }?;
        check_request_size(len)?;
        let value: nextjson::Value = if len == 0 {
            nextjson::Value::Null
        } else {
            if payload.is_null() {
                return Err("non-empty request has a null payload".into());
            }
            let bytes = unsafe { std::slice::from_raw_parts(payload, len) };
            rustbinary::options()
                .deserialize(bytes)
                .map_err(|e| format!("invalid binary request: {e}"))?
        };

        dispatch(method, &value)
    }));

    match result {
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
            assert!(
                s.contains("Corduit") || s.contains("v0.2"),
                "unexpected: {s}"
            );
        }
    }

    fn binary_request(bytes: &[u8]) -> (i32, Vec<u8>) {
        let method = CString::new("get_version").unwrap();
        let response = unsafe { corduit_call_binary(method.as_ptr(), bytes.as_ptr(), bytes.len()) };
        let code = response.code;
        let body = if response.len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(response.data, response.len).to_vec() }
        };
        unsafe { corduit_binary_free(response) };
        (code, body)
    }

    #[test]
    fn binary_call_roundtrip() {
        let params: nextjson::Value = nextjson::from_str(r#"{"mode":1}"#).unwrap();
        let encoded = rustbinary::serialize(&params).unwrap();
        for input in [&encoded[..], &[]] {
            let (code, body) = binary_request(input);
            assert_eq!(code, 0, "{}", String::from_utf8_lossy(&body));
            let value: nextjson::Value = rustbinary::deserialize(&body).unwrap();
            assert_eq!(value.as_str(), Some(api::get_version().as_str()));
        }
    }

    #[test]
    fn malformed_json_cannot_reach_even_a_parameterless_handler() {
        let method = CString::new("get_version").unwrap();
        for input in [&b"{"[..], b"null true", &[0xff]] {
            let args = CString::new(input).unwrap();
            let response = unsafe { corduit_call(method.as_ptr(), args.as_ptr()) };
            let code = response.code;
            unsafe { corduit_string_free(response.data) };
            assert_ne!(code, 0, "accepted malformed input: {input:?}");
        }
    }

    #[test]
    fn malformed_binary_cannot_reach_even_a_parameterless_handler() {
        let mut trailing = rustbinary::serialize(&nextjson::Value::Null).unwrap();
        trailing.push(0);
        let mut truncated = rustbinary::serialize(&"payload").unwrap();
        truncated.pop();
        // A depth beyond the profile ceiling must fail without recursive
        // allocation or dispatch. Build bytes rather than a deep Rust value.
        let array = rustbinary::serialize(&vec![nextjson::Value::Null]).unwrap();
        let mut deep = vec![array[0]; 129];
        deep.extend(rustbinary::serialize(&nextjson::Value::Null).unwrap());
        deep.extend(std::iter::repeat(*array.last().unwrap()).take(129));
        for bytes in [vec![0xfe], trailing, truncated, deep] {
            let (code, error) = binary_request(&bytes);
            assert_ne!(code, 0, "accepted malformed binary input");
            assert!(String::from_utf8(error)
                .unwrap()
                .starts_with("invalid binary request:"));
        }
    }

    #[test]
    fn ffi_rejects_invalid_methods_null_payload_and_oversized_lengths() {
        let method = CString::new(vec![0xff]).unwrap();
        let json = unsafe { corduit_call(method.as_ptr(), ptr::null()) };
        let code = json.code;
        unsafe { corduit_string_free(json.data) };
        assert_ne!(code, 0);
        let binary = unsafe { corduit_call_binary(method.as_ptr(), ptr::null(), 0) };
        let code = binary.code;
        unsafe { corduit_binary_free(binary) };
        assert_ne!(code, 0);

        let method = CString::new("get_version").unwrap();
        let response = unsafe { corduit_call_binary(method.as_ptr(), ptr::null(), 1) };
        let code = response.code;
        unsafe { corduit_binary_free(response) };
        assert_ne!(code, 0);
        assert!(check_request_size(MAX_REQUEST_BYTES).is_ok());
        assert!(check_request_size(MAX_REQUEST_BYTES + 1).is_err());
        assert!(check_request_size(usize::MAX).is_err());
    }

    /// The binary channel must transfer an allocation whose size is exactly
    /// `len` (so the caller can rebuild it from `(data, len)` alone), and
    /// failures must be distinguishable from successes by `code`.
    #[test]
    fn binary_response_owns_exact_allocation_and_errors_carry_code() {
        let mut padded = Vec::with_capacity(4096);
        padded.extend_from_slice(b"corduit");
        let resp = FfiBinaryResponse::ok(padded);
        assert_eq!(resp.code, 0);
        assert_eq!(resp.len, 7);
        assert!(!resp.data.is_null());
        let seen = unsafe { std::slice::from_raw_parts(resp.data, resp.len) };
        assert_eq!(seen, b"corduit");
        unsafe { corduit_binary_free(resp) };

        let err = FfiBinaryResponse::err("boom".to_string());
        assert_ne!(
            err.code, 0,
            "error responses must not carry the success code"
        );
        assert_eq!(err.len, 4);
        unsafe { corduit_binary_free(err) };

        let empty = FfiBinaryResponse::ok(Vec::new());
        assert_eq!(empty.len, 0);
        assert!(empty.data.is_null());
        unsafe { corduit_binary_free(empty) };
    }
}
