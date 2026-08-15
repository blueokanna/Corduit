//! OS-backed randomness helpers.
//!
//! The engine never needs to implement its own entropy gathering: every
//! primitive here is seeded from the operating system's CSPRNG via
//! `getrandom`, and session-level generators (UUIDv4, nonces, ports) use
//! [`crate::crypto::rng::ChaChaRng`] keyed with OS entropy.

use crate::crypto::rng::ChaChaRng;
use crate::crypto::uuid::Uuid;

/// Fill a byte array from OS entropy.
#[inline]
pub fn fill<const N: usize>(buf: &mut [u8; N]) {
    getrandom::fill(buf).expect("OS RNG unavailable");
}

/// A random `u8` from OS entropy.
#[inline]
pub fn u8() -> u8 {
    let mut b = [0u8; 1];
    fill(&mut b);
    b[0]
}

/// A random `u16` (little-endian) from OS entropy.
#[inline]
pub fn u16() -> u16 {
    let mut b = [0u8; 2];
    fill(&mut b);
    u16::from_le_bytes(b)
}

/// A random `u32` (little-endian) from OS entropy.
#[inline]
pub fn u32() -> u32 {
    let mut b = [0u8; 4];
    fill(&mut b);
    u32::from_le_bytes(b)
}

/// A random `u64` (little-endian) from OS entropy.
#[inline]
pub fn u64() -> u64 {
    let mut b = [0u8; 8];
    fill(&mut b);
    u64::from_le_bytes(b)
}

/// A random `N`-byte array from OS entropy.
#[inline]
pub fn bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    fill(&mut b);
    b
}

/// A random RFC 4122 v4 UUID, seeded from OS entropy.
#[inline]
pub fn uuid_v4() -> Uuid {
    let seed = bytes::<32>();
    let mut rng = ChaChaRng::from_seed(&seed);
    Uuid::new_v4(&mut rng)
}
