//! # corduit-crypto
//!
//! Dependency-free, `no_std` cryptographic primitives for the Corduit proxy
//! engine. Every algorithm here is implemented from scratch against the
//! published specification (RFC 1321 / RFC 6234 / FIPS 180-4 / FIPS 202 /
//! RFC 7693 / BLAKE3 spec / RFC 8439 / NIST SP 800-38D / RFC 5869 / RFC 7748).
//! There are no external crate dependencies at all.
//!
//! ## Design
//!
//! * **`no_std` first** — the core of every primitive works on fixed-size
//!   buffers/arrays and needs no allocator. The `alloc` feature only gates
//!   ergonomic `Vec`-returning helpers.
//! * **Constant-time by default** — MAC comparisons, GHASH, AES S-box
//!   lookups and X25519 field arithmetic are written to avoid data-dependent
//!   branches and indexing.
//! * **Small surface** — one trait per concern (`Digest`, `Aead`, `Mac`),
//!   concrete types for everything else. No trait-object indirection in the
//!   hot paths.
//!
//! ## Modules
//!
//! | module        | contents |
//! |---------------|----------|
//! | [`hash`]      | MD5, SHA-1, SHA-2, SHA-3, BLAKE2, BLAKE3 |
//! | [`mac`]       | HMAC, keyed BLAKE2s |
//! | [`stream`]    | ChaCha20, AES block cipher, CTR mode |
//! | [`aead`]      | ChaCha20-Poly1305, AES-GCM |
//! | [`kdf`]       | HKDF |
//! | [`dh`]        | X25519 |
//! | [`encoding`]  | Base64, hex |
//! | [`rng`]       | ChaCha-based deterministic CSPRNG |
//! | [`uuid`]      | RFC 4122 UUID |
//!
//! ## Security notes
//!
//! * This crate performs **no** OS-level entropy gathering. Seeding a
//!   CSPRNG is the caller's responsibility (use the platform RNG, e.g.
//!   `getrandom` in std contexts).
//! * The classic hashes (MD5, SHA-1) are implemented for protocol
//!   compatibility (Shadowsocks/VMess key derivation) and are **not** a
//!   substitute for collision-resistant hashing.
//! * Authenticated decryption always verifies the tag before releasing any
//!   plaintext; never unwrap a message without checking the result.

// `no_std` in normal builds; test builds use the std prelude.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::needless_range_loop)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod aead;
pub mod dh;
pub mod digest;
pub mod encoding;
pub mod hash;
pub mod kdf;
/// Message authentication codes (HMAC, keyed BLAKE2s, Poly1305).
pub mod mac;
pub mod rng;
pub mod stream;
pub mod util;
pub mod uuid;

#[cfg(feature = "alloc")]
pub use aead::Aead;

/// Convenience re-export: `corduit_crypto::digest::Digest`.
pub use digest::Digest;

/// Output buffer size able to hold the largest digest this crate produces
/// (SHA-512 / BLAKE2b-512 = 64 bytes).
pub const MAX_DIGEST_LEN: usize = 64;

/// Largest block size used by any MD-style hash here (SHA-512 / BLAKE2b).
pub const MAX_BLOCK_LEN: usize = 128;

/// Error returned when a key/IV/nonce has an invalid length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidLength;

impl core::fmt::Display for InvalidLength {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid key or nonce length")
    }
}
