#![cfg(target_os = "android")]

use jni::objects::{Global, JObject, JValue};
use jni::sys::jint;
use jni::{EnvUnowned, JavaVM};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, error, info, warn};

extern "C" {
    fn __android_log_write(prio: i32, tag: *const i8, text: *const i8) -> i32;
}

/// Use RwLock instead of OnceLock to allow resetting on VPN restart
static JAVA_VM: RwLock<Option<JavaVM>> = RwLock::new(None);
static VPN_SERVICE: RwLock<Option<Global<JObject<'static>>>> = RwLock::new(None);
static JNI_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[no_mangle]
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
    info!("=== Initializing Rust JNI bridge for VpnService ===");

    // `Env` (which carries `get_java_vm`/`new_global_ref`) is entered through
    // `with_env`. `resolve` turns a Java-exception result into a logged error.
    env.with_env(|env| -> jni::errors::Result<()> {
        // Clear any existing state first to support VPN restart
        {
            let mut vm_guard = JAVA_VM.write();
            let mut service_guard = VPN_SERVICE.write();

            // Drop old references
            *vm_guard = None;
            *service_guard = None;
            JNI_INITIALIZED.store(false, Ordering::SeqCst);

            android_log("INFO", "Cleared previous JNI state");
        }

        // Get and store JavaVM
        let vm = match env.get_java_vm() {
            Ok(vm) => vm,
            Err(e) => {
                let msg = format!("Failed to get JavaVM: {:?}", e);
                android_log("ERROR", &msg);
                error!("{}", msg);
                return Ok(());
            }
        };

        let global_ref = match env.new_global_ref(vpn_service) {
            Ok(global_ref) => global_ref,
            Err(e) => {
                let msg = format!("Failed to create global reference: {:?}", e);
                android_log("ERROR", &msg);
                error!("{}", msg);
                return Ok(());
            }
        };

        {
            let mut vm_guard = JAVA_VM.write();
            let mut service_guard = VPN_SERVICE.write();
            *vm_guard = Some(vm);
            *service_guard = Some(global_ref);
            android_log("INFO", "JavaVM stored successfully");
            info!("JavaVM stored successfully");
            android_log("INFO", "VpnService reference stored successfully");
            info!("VpnService reference stored successfully");
        }

        // Mark as initialized
        JNI_INITIALIZED.store(true, Ordering::SeqCst);

        // Set up the protect callback
        setup_protect_callback();

        android_log("INFO", "=== JNI bridge initialization complete ===");
        info!("=== JNI bridge initialization complete ===");
        Ok(())
    })
    .resolve::<jni::errors::LogErrorAndDefault>()
}

fn android_log(level: &str, message: &str) {
    use std::ffi::CString;

    let tag = CString::new("Corduit-JNI").unwrap_or_default();
    let msg = CString::new(message).unwrap_or_default();

    unsafe {
        let priority = match level {
            "ERROR" => 6, // ANDROID_LOG_ERROR
            "WARN" => 5,  // ANDROID_LOG_WARN
            "INFO" => 4,  // ANDROID_LOG_INFO
            "DEBUG" => 3, // ANDROID_LOG_DEBUG
            _ => 4,
        };
        __android_log_write(
            priority,
            tag.as_ptr() as *const i8,
            msg.as_ptr() as *const i8,
        );
    }
}

#[no_mangle]
pub extern "system" fn Java_com_blueokanna_corduit_CorduitVpnService_nativeClearRustBridge<
    'local,
>(
    _env: EnvUnowned<'local>,
    _vpn_service: JObject<'local>,
) {
    android_log("INFO", "Clearing Rust JNI bridge");
    info!("Clearing Rust JNI bridge");

    // Clear all state to allow re-initialization
    JNI_INITIALIZED.store(false, Ordering::SeqCst);

    {
        let mut vm_guard = JAVA_VM.write();
        let mut service_guard = VPN_SERVICE.write();
        *vm_guard = None;
        *service_guard = None;
    }

    // Clear the protect callback
    corduit_netstack::clear_protect_callback();

    android_log("INFO", "JNI bridge cleared completely");
    info!("JNI bridge cleared completely");
}

pub fn protect_socket_via_jni(fd: i32) -> bool {
    if !JNI_INITIALIZED.load(Ordering::SeqCst) {
        let msg = format!("JNI not initialized, cannot protect socket fd={}", fd);
        android_log("WARN", &msg);
        warn!("{}", msg);
        return false;
    }

    // Hold the read locks for the duration of the JNI call
    let vm_guard = JAVA_VM.read();
    let service_guard = VPN_SERVICE.read();

    let vm = match vm_guard.as_ref() {
        Some(vm) => vm,
        None => {
            let msg = format!("JavaVM not available, cannot protect socket fd={}", fd);
            android_log("WARN", &msg);
            warn!("{}", msg);
            return false;
        }
    };

    let vpn_service_ref = match service_guard.as_ref() {
        Some(service) => service,
        None => {
            let msg = format!("VpnService not available, cannot protect socket fd={}", fd);
            android_log("WARN", &msg);
            warn!("{}", msg);
            return false;
        }
    };

    // jni 0.22: `attach_current_thread` runs a callback with the owned `Env`.
    // Exceptions thrown by `VpnService.protect` surface as `Err`, and any
    // pending Java exception is cleared so the thread can keep using JNI.
    let result: jni::errors::Result<bool> = vm.attach_current_thread(|env| {
        let obj = vpn_service_ref.as_obj();
        match env.call_method(
            obj,
            jni::jni_str!("protect"),
            jni::jni_sig!("(I)Z"),
            &[JValue::Int(fd as jint)],
        ) {
            Ok(ret) => ret.z(),
            Err(e) => {
                if env.exception_check() {
                    env.exception_describe();
                    env.exception_clear();
                }
                Err(e)
            }
        }
    });

    match result {
        Ok(protected) => {
            if protected {
                let msg = format!("Socket fd={} protected successfully via JNI", fd);
                android_log("DEBUG", &msg);
                debug!("{}", msg);
            } else {
                let msg = format!("VpnService.protect() returned false for fd={}", fd);
                android_log("WARN", &msg);
                warn!("{}", msg);
            }
            protected
        }
        Err(e) => {
            let msg = format!("Failed to call VpnService.protect(): {:?}", e);
            android_log("ERROR", &msg);
            error!("{}", msg);
            false
        }
    }
}

/// Set up the protect callback in corduit-solidtcp
fn setup_protect_callback() {
    android_log(
        "INFO",
        "Setting up socket protect callback for corduit-netstack",
    );
    corduit_netstack::set_protect_callback(|fd| {
        let msg = format!("protect_socket callback called for fd={}", fd);
        android_log("DEBUG", &msg);
        protect_socket_via_jni(fd)
    });
    android_log(
        "INFO",
        "Socket protect callback configured for corduit-netstack",
    );
    info!("Socket protect callback configured for corduit-netstack");
}

/// Check if JNI bridge is initialized
pub fn is_jni_initialized() -> bool {
    JNI_INITIALIZED.load(Ordering::SeqCst)
        && JAVA_VM.read().is_some()
        && VPN_SERVICE.read().is_some()
}

/// Get JNI initialization status for debugging
pub fn get_jni_status() -> String {
    let initialized = JNI_INITIALIZED.load(Ordering::SeqCst);
    let has_vm = JAVA_VM.read().is_some();
    let has_service = VPN_SERVICE.read().is_some();
    format!(
        "JNI Status: initialized={}, has_vm={}, has_service={}",
        initialized, has_vm, has_service
    )
}
