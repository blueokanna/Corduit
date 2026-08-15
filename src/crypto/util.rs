//! Internal byte/word helpers and constant-time primitives.

/// Load a big-endian `u32` from `src[0..4]`.
#[inline]
pub(crate) fn load_u32_be(src: &[u8]) -> u32 {
    u32::from_be_bytes([src[0], src[1], src[2], src[3]])
}

/// Load a big-endian `u64` from `src[0..8]`.
#[inline]
pub(crate) fn load_u64_be(src: &[u8]) -> u64 {
    u64::from_be_bytes([
        src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
    ])
}

/// Store a big-endian `u32` into `dst[0..4]`.
#[inline]
pub(crate) fn store_u32_be(dst: &mut [u8], v: u32) {
    dst[..4].copy_from_slice(&v.to_be_bytes());
}

/// Store a big-endian `u64` into `dst[0..8]`.
#[inline]
pub(crate) fn store_u64_be(dst: &mut [u8], v: u64) {
    dst[..8].copy_from_slice(&v.to_be_bytes());
}

/// Load a little-endian `u32` from `src[0..4]`.
#[inline]
pub(crate) fn load_u32_le(src: &[u8]) -> u32 {
    u32::from_le_bytes([src[0], src[1], src[2], src[3]])
}

/// Load a little-endian `u64` from `src[0..8]`.
#[inline]
pub(crate) fn load_u64_le(src: &[u8]) -> u64 {
    u64::from_le_bytes([
        src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
    ])
}

/// Store a little-endian `u32` into `dst[0..4]`.
#[inline]
pub(crate) fn store_u32_le(dst: &mut [u8], v: u32) {
    dst[..4].copy_from_slice(&v.to_le_bytes());
}

/// Store a little-endian `u64` into `dst[0..8]`.
#[inline]
pub(crate) fn store_u64_le(dst: &mut [u8], v: u64) {
    dst[..8].copy_from_slice(&v.to_le_bytes());
}

/// Rotate `x` left by `n` bits.
#[inline(always)]
pub(crate) fn rotl32(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

/// Constant-time equality of two byte slices.
///
/// Returns `true` iff both slices have the same length and identical bytes.
/// The running time is independent of the content (and of the length
/// difference up to the longer slice).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let len = a.len().max(b.len());
    let mut diff = (a.len() ^ b.len()) as u8;
    for i in 0..len {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        diff |= av ^ bv;
    }
    diff == 0
}

/// Constant-time zeroize of a byte slice.
///
/// `core::hint::black_box` fences the writes so the optimizer cannot elide
/// them in release builds (the standard trick used by `zeroize` crates
/// without requiring `unsafe` or volatile asm).
#[inline]
pub fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    core::hint::black_box(buf);
}

/// Zeroize an array.
#[inline]
pub fn zeroize_array<const N: usize>(buf: &mut [u8; N]) {
    zeroize(buf);
}

/// Wipe a whole generic slice-like buffer via volatile writes is not
/// possible without `unsafe`; this is a documented best-effort helper that
/// also prevents the compiler from eliding the writes in release builds for
/// the common `[u8]` case.
#[doc(hidden)]
#[inline]
pub fn zeroize_buf(buf: &mut [u8]) {
    zeroize(buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(!ct_eq(b"a", b"b"));
    }

    #[test]
    fn rotate_roundtrip() {
        assert_eq!(rotl32(0x8000_0000, 1), 1);
    }
}
