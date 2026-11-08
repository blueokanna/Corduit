#[cfg(windows)]
use crate::netstack::error::{NetStackError, Result};

#[cfg(windows)]
use std::path::PathBuf;

#[cfg(windows)]
use tracing::{debug, info, warn};

#[cfg(windows)]
use once_cell::sync::OnceCell;

#[cfg(windows)]
static WINTUN_INSTANCE: OnceCell<wintun_bindings::Wintun> = OnceCell::new();

#[cfg(windows)]
const WINTUN_DLL_BYTES: Option<&[u8]> = None;

/// Wintun download URL
#[cfg(windows)]
const WINTUN_DOWNLOAD_URL: &str = "https://www.wintun.net/builds/wintun-0.14.1.zip";

/// Every place a wintun.dll is looked for, most specific first.
///
/// Only directories the *installer* controls are considered. The working
/// directory and `%LOCALAPPDATA%` used to be on this list; both are writable
/// by the same unelevated user, and the TUN path runs elevated, so a planted
/// DLL there would be loaded with the administrator token — a local
/// privilege-escalation vector. A copy must ship beside the executable (or
/// in `wintun/` under it) to be loadable at all.
#[cfg(windows)]
fn wintun_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(exe_path) = std::env::current_exe()
        && let Some(exe_dir) = exe_path.parent()
    {
        candidates.push(exe_dir.join("wintun.dll"));
        candidates.push(exe_dir.join("wintun").join("wintun.dll"));
    }
    candidates
}

/// Get the path where wintun.dll should be located.
///
/// Returns the first candidate that exists, so a bundled copy beside the
/// executable or a manually unpacked one in `wintun/` is found without the
/// caller knowing which is present. When none exists, the primary location
/// (beside the executable) is returned as the place a download should land.
#[cfg(windows)]
pub fn get_wintun_dll_path() -> Result<PathBuf> {
    let candidates = wintun_candidates();
    if let Some(found) = candidates.iter().find(|path| path.exists()) {
        return Ok(found.clone());
    }
    candidates.into_iter().next().ok_or_else(|| {
        NetStackError::TunError(
            "cannot locate the directory of the running executable, so there is no \
             trusted place to look for wintun.dll"
                .to_string(),
        )
    })
}

/// Check if wintun.dll exists at any known location
#[cfg(windows)]
pub fn is_wintun_available() -> bool {
    wintun_candidates().iter().any(|path| path.exists())
}

/// Extract embedded wintun.dll to the executable directory
#[cfg(windows)]
pub fn extract_wintun_dll() -> Result<PathBuf> {
    let dll_path = get_wintun_dll_path()?;

    if dll_path.exists() {
        debug!("wintun.dll already exists at {:?}", dll_path);
        return Ok(dll_path);
    }

    match WINTUN_DLL_BYTES {
        Some(bytes) => {
            info!("Extracting embedded wintun.dll to {:?}", dll_path);
            std::fs::write(&dll_path, bytes).map_err(|e| {
                NetStackError::TunError(format!("Failed to write wintun.dll: {}", e))
            })?;
            info!("wintun.dll extracted successfully ({} bytes)", bytes.len());
            Ok(dll_path)
        }
        None => {
            warn!("No embedded wintun.dll available");
            warn!("Please download from https://www.wintun.net/ or use download_wintun_dll()");
            Err(NetStackError::TunNotAvailable)
        }
    }
}

/// Ensure wintun.dll is available
#[cfg(windows)]
pub fn ensure_wintun_available() -> Result<PathBuf> {
    if is_wintun_available() {
        get_wintun_dll_path()
    } else {
        extract_wintun_dll()
    }
}

/// Download wintun.dll from the official source.
///
/// The archive lands beside the executable, the only directory this module
/// will later load from; an install directory that cannot be written is an
/// error the user has to resolve (install Wintun system-wide, or run from a
/// writable directory), not a reason to fall back to a user-writable one.
#[cfg(windows)]
pub fn download_wintun_dll() -> Result<PathBuf> {
    let dll_path = get_wintun_dll_path()?;

    if dll_path.exists() {
        return Ok(dll_path);
    }

    info!("Downloading wintun.dll from {}...", WINTUN_DOWNLOAD_URL);

    let client = crate::common::HttpClient::new().with_timeout(std::time::Duration::from_secs(60));

    let response = client
        .get(WINTUN_DOWNLOAD_URL)
        .map_err(|e| NetStackError::TunError(format!("Failed to download wintun: {e}")))?;

    if !response.is_success() {
        return Err(NetStackError::TunError(format!(
            "Failed to download wintun: HTTP {}",
            response.status()
        )));
    }

    #[cfg(target_arch = "x86_64")]
    let dll_name = "wintun/bin/amd64/wintun.dll";
    #[cfg(target_arch = "aarch64")]
    let dll_name = "wintun/bin/arm64/wintun.dll";
    #[cfg(target_arch = "x86")]
    let dll_name = "wintun/bin/x86/wintun.dll";

    let dll_bytes = read_archived_dll(response.bytes(), dll_name)?;
    publish_dll(&dll_path, &dll_bytes)?;

    info!(
        "wintun.dll extracted to {:?} ({} bytes)",
        dll_path,
        dll_bytes.len()
    );
    Ok(dll_path)
}

#[cfg(windows)]
const MAX_DLL_BYTES: u64 = 4 * 1024 * 1024;

/// Read one fixed archive member; never create paths or links from ZIP metadata.
#[cfg(windows)]
fn read_archived_dll(bytes: &[u8], name: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(NetStackError::TunError(
            "Wintun archive exceeds 8 MiB".into(),
        ));
    }
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|e| NetStackError::TunError(format!("Invalid Wintun archive: {e}")))?;
    let file = archive
        .by_name(name)
        .map_err(|e| NetStackError::TunError(format!("Missing Wintun DLL {name}: {e}")))?;
    let expected = file.size();
    if file.is_dir() || file.is_symlink() || expected == 0 || expected > MAX_DLL_BYTES {
        return Err(NetStackError::TunError(
            "Invalid Wintun DLL entry type or size".into(),
        ));
    }
    let mut dll = Vec::with_capacity(expected as usize);
    file.take(MAX_DLL_BYTES + 1)
        .read_to_end(&mut dll)
        .map_err(|e| NetStackError::TunError(format!("Failed to decode Wintun DLL: {e}")))?;
    if dll.len() as u64 != expected || dll.len() as u64 > MAX_DLL_BYTES {
        return Err(NetStackError::TunError(
            "Wintun DLL size does not match its archive entry".into(),
        ));
    }
    Ok(dll)
}

/// Publish only a fully written file. Never truncate an existing installation.
#[cfg(windows)]
fn publish_dll(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .ok_or_else(|| NetStackError::TunError("DLL path has no parent".into()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| NetStackError::TunError(format!("Cannot stage Wintun DLL: {e}")))?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|e| NetStackError::TunError(format!("Cannot write Wintun DLL: {e}")))?;
    temporary
        .persist_noclobber(path)
        .map_err(|e| NetStackError::TunError(format!("Cannot publish Wintun DLL: {}", e.error)))?;
    Ok(())
}

/// Load the wintun library, downloading if necessary
#[cfg(windows)]
pub fn load_wintun() -> Result<&'static wintun_bindings::Wintun> {
    if let Some(wintun) = WINTUN_INSTANCE.get() {
        return Ok(wintun);
    }

    let dll_path = match ensure_wintun_available() {
        Ok(path) => path,
        Err(_) => download_wintun_dll()?,
    };

    info!("Loading wintun.dll from {:?}", dll_path);

    let wintun = unsafe {
        wintun_bindings::load_from_path(&dll_path)
            .map_err(|e| NetStackError::TunError(format!("Failed to load wintun.dll: {}", e)))?
    };

    info!("Wintun library loaded successfully");

    let _ = WINTUN_INSTANCE.set(wintun);
    Ok(WINTUN_INSTANCE.get().unwrap())
}

/// Load wintun synchronously
#[cfg(windows)]
pub fn load_wintun_sync() -> Result<&'static wintun_bindings::Wintun> {
    if let Some(wintun) = WINTUN_INSTANCE.get() {
        return Ok(wintun);
    }

    let dll_path = ensure_wintun_available()?;
    info!("Loading wintun.dll from {:?}", dll_path);

    let wintun = unsafe {
        wintun_bindings::load_from_path(&dll_path)
            .map_err(|e| NetStackError::TunError(format!("Failed to load wintun.dll: {}", e)))?
    };

    info!("Wintun library loaded successfully");

    let _ = WINTUN_INSTANCE.set(wintun);
    Ok(WINTUN_INSTANCE.get().unwrap())
}

/// Get the loaded wintun instance
#[cfg(windows)]
pub fn get_wintun() -> Option<&'static wintun_bindings::Wintun> {
    WINTUN_INSTANCE.get()
}

// Non-Windows stubs
#[cfg(not(windows))]
pub fn is_wintun_available() -> bool {
    true
}

#[cfg(not(windows))]
pub fn ensure_wintun_available() -> Result<std::path::PathBuf> {
    Ok(std::path::PathBuf::new())
}

#[cfg(not(windows))]
use crate::netstack::error::Result;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn test_get_wintun_path() {
        let path = get_wintun_dll_path();
        assert!(path.is_ok());
        assert!(path.unwrap().ends_with("wintun.dll"));
    }
    #[cfg(windows)]
    fn dll_archive(symlink: bool) -> Vec<u8> {
        use std::io::Write;
        let mut archive = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        if symlink {
            archive
                .add_symlink("wintun/bin/amd64/wintun.dll", "outside.dll", options)
                .unwrap();
        } else {
            archive
                .start_file("wintun/bin/amd64/wintun.dll", options)
                .unwrap();
            archive.write_all(b"bounded archive fixture").unwrap();
        }
        archive.finish().unwrap().into_inner()
    }

    #[test]
    #[cfg(windows)]
    fn dll_archive_rejects_links_missing_members_and_hostile_sizes() {
        let name = "wintun/bin/amd64/wintun.dll";
        assert_eq!(
            read_archived_dll(&dll_archive(false), name).unwrap(),
            b"bounded archive fixture"
        );
        assert!(read_archived_dll(&dll_archive(true), name).is_err());
        assert!(read_archived_dll(&dll_archive(false), "wrong-architecture.dll").is_err());
        let mut hostile = dll_archive(false);
        let central = hostile.windows(4).position(|b| b == b"PK\x01\x02").unwrap();
        hostile[central + 24..central + 28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(read_archived_dll(&hostile, name).is_err());
    }

    #[test]
    #[cfg(windows)]
    fn dll_publication_preserves_existing_files_and_cleans_staging_files() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("wintun.dll");
        publish_dll(&target, b"first").unwrap();
        assert!(publish_dll(&target, b"replacement").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"first");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
