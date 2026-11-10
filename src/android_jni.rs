//! The Android JNI bridge.
//!
//! Kotlin/Java calls
//! [`nativeInitRustBridge`](Java_com_blueokanna_corduit_CorduitVpnService_nativeInitRustBridge)
//! once on `CorduitVpnService`
//! creation; from then on any Rust thread may ask the service to
//! `protect(fd)` a socket (the engine's netstack callback). The `JavaVM` and
//! the service reference are kept for the process lifetime and replaced on a
//! VPN restart.
//!
//! Built on `jni` 0.22 with the workspace's Rust 1.88 MSRV. Native entry
//! points receive an FFI-safe `EnvUnowned` and acquire an `Env` before using
//! JNI. Android supplies the VM; the JVM invocation feature stays disabled.
//!
//! Both exported functions catch panics: unwinding across an `extern
//! "system"` boundary aborts the process, and a panic in the bridge must not
//! take the Android app down.

use jni::objects::{Global, JObject, JValue};
use jni::sys::jint;
use jni::{Env, EnvUnowned, JavaVM, Outcome, jni_sig, jni_str};
use parking_lot::RwLock;
use std::ffi::CString;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, error, info, warn};

unsafe extern "C" {
    fn __android_log_write(
        prio: i32,
        tag: *const std::os::raw::c_char,
        text: *const std::os::raw::c_char,
    ) -> i32;
}

/// `JavaVM` and the `VpnService` reference are process-wide and swapped on
/// restart, so they live behind `RwLock` rather than `OnceLock`.
static JAVA_VM: RwLock<Option<JavaVM>> = RwLock::new(None);
static VPN_SERVICE: RwLock<Option<Global<JObject<'static>>>> = RwLock::new(None);
static JNI_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Store the VM and the service, replacing whatever a previous VPN session
/// left behind.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_blueokanna_corduit_CorduitVpnService_nativeInitRustBridge<
    'local,
>(
    mut env: EnvUnowned<'local>,
    vpn_service: JObject<'local>,
) {
    android_log(
        "INFO",
        "=== Initializing Rust JNI bridge for VpnService ===",
    );
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        env.with_env(|env| {
            let result = init_bridge(env, vpn_service);
            if let Err(error) = &result {
                report_java_exception(env, &format!("bridge initialization failed: {error}"));
            }
            result
        })
        .into_outcome()
    }));
    match outcome {
        Ok(Outcome::Ok(())) => {
            info!("JNI bridge initialized");
            android_log("INFO", "=== JNI bridge initialization complete ===");
        }
        Ok(Outcome::Err(e)) => {
            let message = format!("JNI bridge initialization failed: {e}");
            error!("{message}");
            android_log("ERROR", &message);
        }
        Ok(Outcome::Panic(_)) | Err(_) => {
            clear_state();
            error!("JNI bridge initialization panicked");
            android_log("ERROR", "JNI bridge initialization panicked");
        }
    }
}

/// Drop every stored reference so the next session starts clean.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_blueokanna_corduit_CorduitVpnService_nativeClearRustBridge<
    'local,
>(
    mut env: EnvUnowned<'local>,
    _vpn_service: JObject<'local>,
) {
    android_log("INFO", "Clearing Rust JNI bridge");
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        env.with_env(|_| {
            clear_bridge();
            Ok::<(), jni::errors::Error>(())
        })
        .into_outcome()
    }));
    if !matches!(outcome, Ok(Outcome::Ok(()))) {
        error!("JNI bridge teardown panicked");
        android_log("ERROR", "JNI bridge teardown panicked");
    }
}

/// Perform the store half of initialization.
fn init_bridge(env: &Env, vpn_service: JObject) -> jni::errors::Result<()> {
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
/// Java call fails. The attachment scope captures exceptions thrown by
/// `protect` and restores any exception that was pending before this call.
pub fn protect_socket_via_jni(fd: i32) -> bool {
    if !JNI_INITIALIZED.load(Ordering::SeqCst) {
        warn!("JNI not initialized, cannot protect socket fd={fd}");
        return false;
    }

    let vm_guard = JAVA_VM.read();
    let service_guard = VPN_SERVICE.read();
    let (Some(vm), Some(service)) = (vm_guard.as_ref(), service_guard.as_ref()) else {
        warn!("JNI bridge has no VM/service, cannot protect socket fd={fd}");
        return false;
    };

    let result: jni::errors::Result<bool> = vm.attach_current_thread(|env| {
        env.call_method(
            service.as_obj(),
            jni_str!("protect"),
            jni_sig!("(I)Z"),
            &[JValue::Int(fd as jint)],
        )?
        .z()
    });
    match result {
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
            let message = format!("VpnService.protect() failed for fd={fd}: {e}");
            error!("{message}");
            android_log("ERROR", &message);
            false
        }
    }
}

/// Describe and clear a pending Java exception, then log the failure.
fn report_java_exception(env: &mut Env, context: &str) {
    if env.exception_check() {
        env.exception_describe();
        env.exception_clear();
    }
    let message = format!("JNI call failed: {context}");
    error!("{message}");
    android_log("ERROR", &message);
}

/// Install the netstack callback that protects outbound sockets.
fn setup_protect_callback() {
    android_log(
        "INFO",
        "Setting up socket protect callback for corduit-netstack",
    );
    crate::netstack::set_protect_callback(protect_socket_via_jni);
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
