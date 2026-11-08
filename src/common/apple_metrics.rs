//! iOS metrics from public Mach and sysctl interfaces. No process enumeration.
#![allow(unsafe_code)]

use crate::engine::error::{Error, Result};
use crate::types::SystemInfo;
use mach2::mach_init::mach_host_self;
use mach2::mach_port::mach_port_deallocate;
use mach2::traps::mach_task_self;
use parking_lot::Mutex;
use std::ffi::CStr;
use std::mem::MaybeUninit;

/// Current RSS in bytes, matching the unit used by other platforms.
pub(crate) fn resident_memory() -> Result<u64> {
    let mut info = MaybeUninit::<libc::mach_task_basic_info>::zeroed();
    let mut count = libc::MACH_TASK_BASIC_INFO_COUNT;
    // SAFETY: the flavor, buffer size and count describe the same C struct.
    // mach_task_self is a borrowed task port; it must not be deallocated.
    let result = unsafe {
        libc::task_info(
            mach_task_self(),
            libc::MACH_TASK_BASIC_INFO,
            info.as_mut_ptr().cast(),
            &mut count,
        )
    };
    if result != libc::KERN_SUCCESS || count < libc::MACH_TASK_BASIC_INFO_COUNT {
        return Err(Error::network(format!(
            "Cannot read task memory: Mach status {result}"
        )));
    }
    // SAFETY: a successful task_info filled the complete structure; reading
    // the packed resident_size field by value does not create an unaligned reference.
    Ok(unsafe { info.assume_init() }.resident_size)
}

struct HostPort(libc::mach_port_t);
impl Drop for HostPort {
    fn drop(&mut self) {
        // SAFETY: this releases only the send right obtained by mach_host_self.
        unsafe {
            mach_port_deallocate(mach_task_self(), self.0);
        }
    }
}

fn cpu_ticks() -> Result<[u32; 4]> {
    // SAFETY: acquiring this process's host send right takes no pointer arguments.
    let host = HostPort(unsafe { mach_host_self() });
    let mut info = MaybeUninit::<libc::host_cpu_load_info>::zeroed();
    let mut count = libc::HOST_CPU_LOAD_INFO_COUNT;
    // SAFETY: the buffer and count match HOST_CPU_LOAD_INFO; the host right
    // remains owned until this call finishes, including the failure path.
    let result = unsafe {
        libc::host_statistics(
            host.0,
            libc::HOST_CPU_LOAD_INFO,
            info.as_mut_ptr().cast(),
            &mut count,
        )
    };
    if result != libc::KERN_SUCCESS || count < libc::HOST_CPU_LOAD_INFO_COUNT {
        return Err(Error::network(format!(
            "Cannot read CPU ticks: Mach status {result}"
        )));
    }
    // SAFETY: successful host_statistics initialized all four counters.
    Ok(unsafe { info.assume_init() }.cpu_ticks)
}

fn sysctl_bytes(name: &CStr, output: &mut [u8]) -> Result<usize> {
    let mut length = output.len();
    // SAFETY: name is NUL terminated, output is writable for length bytes,
    // and null newp/zero newlen make this a read-only query.
    let result = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            output.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 || length > output.len() {
        return Err(Error::network(format!(
            "Cannot read {}: {}",
            name.to_string_lossy(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(length)
}

fn sysctl_u32(name: &CStr) -> Result<u32> {
    let mut bytes = [0; 4];
    if sysctl_bytes(name, &mut bytes)? != bytes.len() {
        return Err(Error::network("Unexpected CPU property size"));
    }
    Ok(u32::from_ne_bytes(bytes))
}

pub(crate) fn system_info() -> Result<SystemInfo> {
    let mut memory = [0; 8];
    if sysctl_bytes(c"hw.memsize", &mut memory)? != memory.len() {
        return Err(Error::network("Unexpected physical memory property size"));
    }
    let threads = sysctl_u32(c"hw.logicalcpu")?;
    let cores = sysctl_u32(c"hw.physicalcpu")?;
    let mut brand = [0; 128];
    let cpu_name = sysctl_bytes(c"machdep.cpu.brand_string", &mut brand)
        .ok()
        .and_then(|size| CStr::from_bytes_until_nul(&brand[..size]).ok())
        .and_then(|value| value.to_str().ok())
        .filter(|name| !name.is_empty())
        .unwrap_or(std::env::consts::ARCH)
        .to_owned();
    static PREVIOUS: Mutex<Option<[u32; 4]>> = Mutex::new(None);
    let cpu_usage = {
        let mut previous = PREVIOUS.lock();
        let current = cpu_ticks()?;
        let usage = previous.map_or(0.0, |old| usage_between(old, current));
        *previous = Some(current);
        usage
    };
    Ok(SystemInfo {
        platform: "iOS".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        memory_total: u64::from_ne_bytes(memory),
        memory_used: resident_memory()?,
        cpu_cores: cores,
        cpu_threads: threads,
        cpu_name,
        cpu_usage,
    })
}

fn usage_between(previous: [u32; 4], current: [u32; 4]) -> f64 {
    let delta: [u64; 4] = std::array::from_fn(|i| u64::from(current[i].wrapping_sub(previous[i])));
    let total: u64 = delta.iter().sum();
    if total == 0 {
        0.0
    } else {
        100.0 * (total - delta[libc::CPU_STATE_IDLE as usize]) as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn cpu_samples_handle_idle_intervals_and_counter_wrap() {
        assert_eq!(super::usage_between([1, 2, 3, 4], [1, 2, 3, 4]), 0.0);
        assert_eq!(super::usage_between([0; 4], [0, 0, 20, 0]), 0.0);
        let usage = super::usage_between([u32::MAX - 1, 10, 20, 30], [1, 11, 22, 30]);
        assert!((usage - 100.0 * 4.0 / 6.0).abs() < 1e-10);
    }

    #[test]
    fn mach_samples_describe_the_current_process_and_host() {
        assert!(super::resident_memory().unwrap() > 0);
        for _ in 0..2 {
            let info = super::system_info().unwrap();
            assert!(info.memory_total > 0 && info.memory_used > 0);
            assert!(info.cpu_cores > 0 && info.cpu_threads >= info.cpu_cores);
            assert!((0.0..=100.0).contains(&info.cpu_usage));
        }
    }
}
