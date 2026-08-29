//! System root-certificate loading for courierust's TLS stack.
//!
//! courierust deliberately ships no bundled roots and cannot reach into the
//! OS trust store itself, so Corduit loads them per platform:
//!
//! * **Windows** — enumerate the `ROOT` system store (via the `windows`
//!   crate) and take each certificate's DER encoding.
//! * **Linux** — read the distribution CA bundle
//!   (`/etc/ssl/certs/ca-certificates.crt` on Debian/Ubuntu,
//!   `/etc/pki/tls/certs/ca-bundle.crt` on RHEL/Fedora) and parse the PEM
//!   blocks.
//! * **Android** — read `/system/etc/security/cacerts/` (a directory of
//!   PEM files with hashed names).
//!
//! Everything is cached in a process-wide [`OnceLock`] — the store is small
//! (tens of KB) and loading it once per process is the right trade-off. A
//! host with no readable store falls back to an empty store, which makes
//! certificate validation fail closed (never silently accept).

use courierust::courierust_tls::RootStore;
use std::sync::OnceLock;

/// Load (once per process) and return the system root store.
pub fn system_root_store() -> &'static RootStore {
    static STORE: OnceLock<RootStore> = OnceLock::new();
    STORE.get_or_init(load)
}

fn load() -> RootStore {
    let mut store = RootStore::new();
    for der in collect_root_der() {
        store.add_der(der);
    }
    store
}

#[cfg(windows)]
// SAFETY: the only `unsafe` in this module (and, by extension, in `common`)
// is the Win32 certificate-store enumeration below. Every pointer handed
// back by `CertEnumCertificatesInStore` is owned by the store and must NOT
// be freed individually; the store itself is closed exactly once. The DER
// slices are copied out before the store is closed.
#[allow(unsafe_code)]
fn collect_root_der() -> Vec<Vec<u8>> {
    use windows::core::PCWSTR;
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertEnumCertificatesInStore, CertOpenSystemStoreW, CERT_CONTEXT,
    };

    let mut certs = Vec::new();
    let store = unsafe { CertOpenSystemStoreW(None, PCWSTR(windows::core::w!("ROOT").as_ptr())) };
    let Ok(store) = store else {
        return certs;
    };
    unsafe {
        let mut current: *const CERT_CONTEXT = CertEnumCertificatesInStore(store, None);
        while !current.is_null() {
            let ctx = &*current;
            let der = std::slice::from_raw_parts(ctx.pbCertEncoded, ctx.cbCertEncoded as usize);
            certs.push(der.to_vec());
            current = CertEnumCertificatesInStore(store, Some(current));
        }
    }
    let _ = unsafe { CertCloseStore(Some(store), 0) };
    certs
}

#[cfg(not(windows))]
fn collect_root_der() -> Vec<Vec<u8>> {
    let mut out = Vec::new();

    // Linux / generic UNIX: a PEM bundle or a directory of PEM files.
    for path in [
        "/etc/ssl/certs/ca-certificates.crt", // Debian / Ubuntu / Android host
        "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL / Fedora
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    ] {
        if let Ok(pem) = std::fs::read_to_string(path) {
            if let Ok(der) = parse_pem_bundle(&pem) {
                out.extend(der);
                return out;
            }
        }
    }

    // Android: hashed PEM files in a directory.
    if let Ok(entries) = std::fs::read_dir("/system/etc/security/cacerts") {
        let mut files: Vec<_> = entries.filter_map(Result::ok).collect();
        files.sort_by_key(|e| e.file_name());
        for entry in files {
            let Ok(path) = entry.path().into_os_string().into_string() else {
                continue;
            };
            if let Ok(pem) = std::fs::read_to_string(&path) {
                if let Ok(der) = parse_pem_bundle(&pem) {
                    out.extend(der);
                }
            }
        }
        if !out.is_empty() {
            return out;
        }
    }

    out
}

/// Extract every `-----BEGIN CERTIFICATE-----` DER block from a PEM bundle.
/// (Also used by the TLS identity loader in [`crate::common::http_server`].)
pub(crate) fn parse_pem_bundle(pem: &str) -> std::io::Result<Vec<Vec<u8>>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let Some(end) = after.find(END) else {
            break;
        };
        let b64 = &after[..end];
        let der = base64_decode(b64)?;
        out.push(der);
        rest = &after[end + END.len()..];
    }
    Ok(out)
}

/// Decode standard base64 without pulling in a dependency (roots.rs stays
/// self-contained; the base64 alphabet is fixed and length-bounded by the
/// PEM input).
pub(crate) fn base64_decode(input: &str) -> std::io::Result<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for ch in input.bytes() {
        if ch == b'\r' || ch == b'\n' || ch == b' ' {
            continue;
        }
        let val = if ch == b'=' {
            break;
        } else {
            TABLE.iter().position(|&c| c == ch).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid base64 byte 0x{ch:02x}"),
                )
            })? as u32
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pem_bundle() {
        // A real (public) root: the ISRG Root X1 certificate, base64 body
        // truncated to the header + a couple of lines to keep the test
        // self-contained; parse must at least not panic and produce zero
        // or one certificate without error.
        let pem = "\
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
-----END CERTIFICATE-----
";
        let der = parse_pem_bundle(pem).unwrap();
        assert_eq!(der.len(), 1);
        assert!(der[0].len() > 50);
    }

    #[test]
    fn rejects_garbage_base64() {
        assert!(base64_decode("!!!not-base64!!!").is_err());
    }

    #[test]
    fn decodes_empty_and_padding() {
        assert_eq!(base64_decode("").unwrap(), Vec::<u8>::new());
        // "aGVsbG8=" == b"hello"
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
    }
}
