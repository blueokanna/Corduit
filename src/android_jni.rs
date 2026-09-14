//! The Android JNI bridge.
//!
//! Kotlin/Java calls [`nativeInitRustBridge`] once on `CorduitVpnService`
//! creation; from then on any Rust thread may ask the service to
//! `protect(fd)` a socket (the engine's netstack callback). The `JavaVM` and
//! the service reference are kept for the process lifetime and replaced on a
//! VPN restart.
//!
//! Built on `jni` 0.21, which is the last release line that compiles on the
//! workspace's MSRV (Rust 1.78): `jni` 0.22 is edition 2024 and requires
//! Rust 1.85. Only the JNI surface the bridge actually uses is pulled in —
//! 0.21 keeps the JVM *invocation* feature (and with it `libloading` and
//! `java-locator`) off by default, and Android always hands us a live VM.
//!
//! Both exported functions catch panics: unwinding across an `extern
//! "system"` boundary aborts the process, and a panic in the bridge must not
//! take the Android app down.

use jni::objects::{GlobalRef, JObject, JValue};
use jni::sys::jint;
use jni::{JNIEnv, JavaVM};
use parking_lot::RwLock;
use std::ffi::CString;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, error, info, warn};

extern "C" {
    fn __android_log_write(
        prio: i32,
        tag: *const std::os::raw::c_char,
        text: *const std::os::raw::c_char,
    ) -> i32;
}

/// `JavaVM` and the `VpnService` reference are process-wide and swapped on
/// restart, so they live behind `RwLock` rather than `OnceLock`.
static JAVA_VM: RwLock<Option<JavaVM>> = RwLock::new(None);
static VPN_SERVICE: RwLock<Option<GlobalRef>> = RwLock::new(None);
static JNI_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Store the VM and the service, replacing whatever a previous VPN session
/// left behind.
#[no_mangle]
pub extern "system" fn Java_com_blueokanna_corduit_CorduitVpnService_nativeInitRustBridge<
    'local,
>(
    env: JNIEnv<'local>,
    vpn_service: JObject<'local>,
) {
    android_log(
        "INFO",
        "=== Initializing Rust JNI bridge for VpnService ===",
    );
    let outcome = catch_unwind(AssertUnwindSafe(|| init_bridge(&env, vpn_service)));
    match outcome {
        Ok(Ok(())) => {
            info!("JNI bridge initialized");
            android_log("INFO", "=== JNI bridge initialization complete ===");
        }
        Ok(Err(e)) => {
            let message = format!("JNI bridge initialization failed: {e}");
            error!("{message}");
            android_log("ERROR", &message);
        }
        Err(_) => {
            // Recover the lock state a panicking initializer may have left
            // behind: a poisoned bridge would otherwise never initialize.
            clear_state();
            error!("JNI bridge initialization panicked");
            android_log("ERROR", "JNI bridge initialization panicked");
        }
    }
}

/// Drop every stored reference so the next session starts clean.
#[no_mangle]
pub extern "system" fn Java_com_blueokanna_corduit_CorduitVpnService_nativeClearRustBridge<
    'local,
>(
    _env: JNIEnv<'local>,
    _vpn_service: JObject<'local>,
) {
    android_log("INFO", "Clearing Rust JNI bridge");
    let outcome = catch_unwind(AssertUnwindSafe(clear_bridge));
    if outcome.is_err() {
        error!("JNI bridge teardown panicked");
        android_log("ERROR", "JNI bridge teardown panicked");
    }
}

/// Perform the store half of initialization.
fn init_bridge(env: &JNIEnv, vpn_service: JObject) -> jni::errors::Result<()> {
    // Clear first: a restarted VPN service must not keep the old instance.
    clear_state();

    let vm = env.get_java_vm()?;
    let service = env.new_global_ref(vpn_service)?;

    {
        let mut vm_slot = JAVA_VM.write();
        let mut service_slot = VPN_SERVICE.write();
        *vm_slot = Some(vm);
        *service_slot = Some(service);
    }
    JNI_INITIALIZED.store(true, Ordering::SeqCst);
    setup_protect_callback();
    Ok(())
}

/// Clear the state and the netstack protect callback.
fn clear_bridge() {
    JNI_INITIALIZED.store(false, Ordering::SeqCst);
    clear_state();
    crate::netstack::clear_protect_callback();
    info!("JNI bridge cleared");
}

/// Drop the stored VM/service without touching the netstack callback.
fn clear_state() {
    let mut vm_slot = JAVA_VM.write();
    let mut service_slot = VPN_SERVICE.write();
    *vm_slot = None;
    *service_slot = None;
    JNI_INITIALIZED.store(false, Ordering::SeqCst);
}

/// Ask `VpnService.protect(fd)` to exempt a socket from the tunnel.
///
/// Returns `false` (with a log line) whenever the bridge is not ready or the
/// Java call fails; an exception thrown by `protect` is described, cleared
/// and reported rather than left pending for the next JNI call to trip over.
pub fn protect_socket_via_jni(fd: i32) -> bool {
    if !JNI_INITIALIZED.load(Ordering::SeqCst) {
        warn!("JNI not initialized, cannot protect socket fd={fd}");
        return false;
    }

    // Hold the read guards for the duration of the call: they keep the VM
    // and the service reference alive.
    let vm_guard = JAVA_VM.read();
    let service_guard = VPN_SERVICE.read();
    let (Some(vm), Some(service)) = (vm_guard.as_ref(), service_guard.as_ref()) else {
        warn!("JNI bridge has no VM/service, cannot protect socket fd={fd}");
        return false;
    };

    // `attach_current_thread_permanently` attaches a worker thread on first
    // use and keeps it attached: the callback fires once per socket, and a
    // detach/attach pair per call is pure JVM bookkeeping overhead.
    let mut env = match vm.attach_current_thread_permanently() {
        Ok(env) => env,
        Err(e) => {
            let message = format!("Failed to attach thread to the JVM: {e}");
            error!("{message}");
            android_log("ERROR", &message);
            return false;
        }
    };

    match env.call_method(
        service.as_obj(),
        "protect",
        "(I)Z",
        &[JValue::Int(fd as jint)],
    ) {
        Ok(value) => match value.z() {
            Ok(true) => {
                debug!("Socket fd={fd} protected");
                true
            }
            Ok(false) => {
                let message = format!("VpnService.protect() returned false for fd={fd}");
                warn!("{message}");
                android_log("WARN", &message);
                false
            }
            Err(e) => {
                report_java_exception(&mut env, &format!("protect() returned no boolean: {e}"));
                false
            }
        },
        Err(e) => {
            report_java_exception(&mut env, &format!("VpnService.protect() failed: {e}"));
            false
        }
    }
}

/// Describe and clear a pending Java exception, then log the failure.
fn report_java_exception(env: &mut JNIEnv, context: &str) {
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_describe();
        let _ = env.exception_clear();
    }
    let message = format!("Failed to call VpnService.protect(): {context}");
    error!("{message}");
    android_log("ERROR", &message);
}

/// Install the netstack callback that protects outbound sockets.
fn setup_protect_callback() {
    android_log(
        "INFO",
        "Setting up socket protect callback for corduit-netstack",
    );
    crate::netstack::set_protect_callback(|fd| protect_socket_via_jni(fd));
    android_log(
        "INFO",
        "Socket protect callback configured for corduit-netstack",
    );
}

/// Whether the bridge holds a VM and a service reference.
pub fn is_jni_initialized() -> bool {
    JNI_INITIALIZED.load(Ordering::SeqCst)
        && JAVA_VM.read().is_some()
        && VPN_SERVICE.read().is_some()
}

/// A one-line description of the bridge state, for `get_status`.
pub fn get_jni_status() -> String {
    format!(
        "JNI Status: initialized={}, has_vm={}, has_service={}",
        JNI_INITIALIZED.load(Ordering::SeqCst),
        JAVA_VM.read().is_some(),
        VPN_SERVICE.read().is_some()
    )
}

/// Write one line to logcat, for messages that must be visible even when the
/// `tracing` subscriber is not installed yet.
fn android_log(level: &str, message: &str) {
    let Ok(tag) = CString::new("Corduit-JNI") else {
        return;
    };
    let Ok(text) = CString::new(message) else {
        return;
    };
    let priority = match level {
        "ERROR" => 6, // ANDROID_LOG_ERROR
        "WARN" => 5,  // ANDROID_LOG_WARN
        "DEBUG" => 3, // ANDROID_LOG_DEBUG
        _ => 4,       // ANDROID_LOG_INFO
    };
    unsafe {
        __android_log_write(priority, tag.as_ptr(), text.as_ptr());
    }
}
