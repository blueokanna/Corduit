//! Core streaming-hash trait used by all MD-style digests and by the
//! generic HMAC / HKDF constructions.

/// A Merkle–Damgård style incremental hash.
///
/// The `finalize_into` form is the canonical finalization because it avoids
/// generic-constant array sizes; concrete hash types additionally provide
/// inherent `finalize() -> [u8; N]` and `digest(data) -> [u8; N]` helpers.
pub trait Digest: Sized {
    /// Output length in bytes.
    const OUTPUT_LEN: usize;
    /// Compression block length in bytes.
    const BLOCK_LEN: usize;

    /// Create a fresh hasher in the initial state.
    fn new() -> Self;

    /// Absorb `data` into the running state.
    fn update(&mut self, data: &[u8]);

    /// Finalize, writing exactly [`Self::OUTPUT_LEN`] bytes into `out`.
    ///
    /// Panics in debug builds if `out.len() < Self::OUTPUT_LEN`.
    fn finalize_into(self, out: &mut [u8]);

    /// One-shot digest into a caller-provided buffer.
    fn digest_into(data: &[u8], out: &mut [u8]) {
        let mut h = Self::new();
        h.update(data);
        h.finalize_into(out);
    }
}
