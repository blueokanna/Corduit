//! GHASH field arithmetic on the CPU's carry-less multiply instructions:
//! `PCLMULQDQ` (x86/x86_64) and `PMULL` (aarch64).
//!
//! AES-GCM authenticates with GHASH — one GF(2^128) multiply per 16-byte
//! block ([`GHash`](super::aes_gcm) in this module's parent). The software
//! multiply walks 128 bits one at a time; these instructions compute a 64×64
//! carry-less product in one go, so a whole multiply becomes three of them
//! plus a fixed reduction.
//!
//! # Computing GHASH as POLYVAL
//!
//! GHASH's reduction polynomial (`x^128 + x^7 + x^2 + x + 1`) folds from the
//! low end, one bit at a time, which is why no carry-less implementation
//! computes it directly: it uses its "reverse", POLYVAL's
//! `x^128 + x^127 + x^126 + x^121 + 1` (RFC 8452 Appendix A), whose reduction
//! is plain lane shifts. So the pipeline is: apply `mulx_POLYVAL` to the
//! GHASH subkey once ([`prepare`]), feed each GHASH block through unchanged,
//! and the POLYVAL state *is* the GHASH product ([`PreparedKey::mul`]). The
//! byte order needs no conversion at either end — a block read as a
//! big-endian `u128` is exactly the value the POLYVAL core expects — and the
//! agreement test against the software multiply below pins every one of those
//! claims down on hardware that can run it.
//!
//! The multiply-and-reduce sequence is the one from the RustCrypto `polyval`
//! crate's `CLMUL` backend (`backend/clmul.rs`, itself verified against the
//! NIST GCM vectors): three `clmul64`s for the 128×128 product (Karatsuba)
//! and a shift/XOR reduction. Every step of that sequence is local to a
//! 64-bit lane, so it is kept here as *scalar* code over `u128` lane helpers:
//! one implementation shared by both architectures, with only the 64×64
//! primitive per-architecture — the part that cannot be shared is exactly the
//! part that is one instruction.
//!
//! # Availability
//!
//! * `target_feature = "pclmulqdq"` / `"pmull"` (the crate was compiled for
//!   a CPU that has it): always used;
//! * x86/x86_64: one CPUID leaf-1 probe — `ECX.PCLMULQDQ` (bit 1), plus
//!   `EDX.SSE` and `EDX.FXSR` so an OS that does not save the XMM state is
//!   excluded; probeable without `std`, same pattern as
//!   [`aes_hw`](crate::crypto::stream);
//! * aarch64 with `std`: `is_aarch64_feature_detected!("pmull")` (HWCAP);
//! * everything else: no back end — [`prepare`] answers `None` and the
//!   caller keeps multiplying in software.
//!
//! # Safety
//!
//! One of the crate's four audited `unsafe` sites (the list lives in
//! [`crate::common`]). The unsafe surface is exactly the CPUID / HWCAP probe
//! and one `#[target_feature(enable = …)]` `clmul64` per architecture.
//! Everything else is sound by construction: a [`PreparedKey`] cannot exist
//! unless [`prepare`] saw [`available`] return `true`, and a CPU's features
//! do not regress at runtime, so [`dot`]'s reachability of the instructions
//! is guaranteed before it runs. Nothing here touches memory outside the
//! caller's values.

#![allow(unsafe_code)]

// ---------------------------------------------------------------------------
// x86 / x86_64 — PCLMULQDQ
// ---------------------------------------------------------------------------

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86 {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::{
        __cpuid, __m128i, _mm_clmulepi64_si128, _mm_set_epi64x, _mm_storeu_si128,
    };
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::{
        __cpuid, __m128i, _mm_clmulepi64_si128, _mm_set_epi64x, _mm_storeu_si128,
    };
    use core::sync::atomic::{AtomicU8, Ordering};

    /// `0` unknown, `1` absent, `2` present.
    static AVAILABLE: AtomicU8 = AtomicU8::new(0);

    /// Whether `PCLMULQDQ` may be executed on this CPU (and this OS keeps XMM
    /// state across context switches).
    pub fn available() -> bool {
        if cfg!(target_feature = "pclmulqdq") {
            return true;
        }
        match AVAILABLE.load(Ordering::Relaxed) {
            1 => false,
            2 => true,
            _ => {
                // Safety: CPUID is part of the x86 ISA; leaf 1 is the
                // feature-information leaf every CPU answers without any
                // enable bit, and the call has no memory effects. (Newer
                // toolchains declare `__cpuid` safe, 1.78 still declares it
                // `unsafe fn`; the allow keeps both warning-free.)
                #[allow(unused_unsafe)]
                let leaf = unsafe { __cpuid(1) };
                /// CPUID.1:ECX[1] — PCLMULQDQ.
                const PCLMULQDQ: u32 = 1 << 1;
                /// CPUID.1:EDX[25] — SSE.
                const SSE: u32 = 1 << 25;
                /// CPUID.1:EDX[24] — FXSAVE/FXRSTOR (the OS saves XMM state).
                const FXSR: u32 = 1 << 24;
                let present = leaf.ecx & PCLMULQDQ != 0 && leaf.edx & (SSE | FXSR) == (SSE | FXSR);
                AVAILABLE.store(if present { 2 } else { 1 }, Ordering::Relaxed);
                present
            }
        }
    }

    /// `a ⊗ b`: the 64×64 carry-less product, as a 128-bit value.
    ///
    /// # Safety
    /// [`available`] must have returned `true` on this CPU.
    #[target_feature(enable = "pclmulqdq")]
    pub unsafe fn clmul64(a: u64, b: u64) -> u128 {
        // `_mm_set_epi64x` rather than the x86_64-only `_mm_cvtsi64_si128`:
        // one source compiles (and emits the same `movq`) on both x86 widths.
        let product = _mm_clmulepi64_si128(
            _mm_set_epi64x(0, a as i64),
            _mm_set_epi64x(0, b as i64),
            0x00,
        );
        // The lane pair is the full product: low half in lane 0, high half in
        // lane 1. Reading it back as little-endian `u128` gives exactly that.
        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, product);
        u128::from_le_bytes(out)
    }
}

// ---------------------------------------------------------------------------
// aarch64 — PMULL
// ---------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
mod arm {
    use core::arch::aarch64::vmull_p64;

    #[cfg(feature = "std")]
    use core::sync::atomic::{AtomicU8, Ordering};

    /// `0` unknown, `1` absent, `2` present.
    #[cfg(feature = "std")]
    static AVAILABLE: AtomicU8 = AtomicU8::new(0);

    /// HWCAP detection, cached; `std` is the only portable source for it.
    #[cfg(feature = "std")]
    fn detected() -> bool {
        match AVAILABLE.load(Ordering::Relaxed) {
            1 => false,
            2 => true,
            _ => {
                let present = std::arch::is_aarch64_feature_detected!("pmull");
                AVAILABLE.store(if present { 2 } else { 1 }, Ordering::Relaxed);
                present
            }
        }
    }

    /// Without `std` there is no portable HWCAP read: the software multiply
    /// (or a compile-time `pmull` target feature) is all that is left.
    #[cfg(not(feature = "std"))]
    fn detected() -> bool {
        false
    }

    /// Whether the CPU implements the ARMv8 carry-less multiply.
    pub fn available() -> bool {
        cfg!(target_feature = "pmull") || detected()
    }

    /// `a ⊗ b`: the 64×64 carry-less product, as a 128-bit value.
    ///
    /// No `target_feature` attribute: NEON is baseline on aarch64 and PMULL
    /// use is gated by [`available`] alone (`pmull` is not even a codegen
    /// feature name). Same shape as the reference implementations.
    ///
    /// # Safety
    /// [`available`] must have returned `true` on this CPU.
    pub unsafe fn clmul64(a: u64, b: u64) -> u128 {
        vmull_p64(a, b)
    }
}

// ---------------------------------------------------------------------------
// The shared multiply
// ---------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
use arm as back_end;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86 as back_end;

/// Whether the platform's carry-less multiply is usable on this CPU.
///
/// Architectures without a back end always answer `false`, which is what
/// keeps [`prepare`] returning `None` there.
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
pub fn available() -> bool {
    back_end::available()
}

/// Architectures without a carry-less multiply back end: the caller's
/// software multiply is the only implementation, so nothing is available.
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
pub fn available() -> bool {
    false
}

/// 64×64 carry-less product, per architecture.
///
/// # Safety
/// [`available`] must have returned `true` on this CPU.
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
#[inline]
unsafe fn clmul64(a: u64, b: u64) -> u128 {
    back_end::clmul64(a, b)
}

/// Unreachable stand-in for architectures without a back end: [`prepare`]
/// refuses to build a [`PreparedKey`] there, so [`dot`] — its only caller —
/// cannot run.
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
unsafe fn clmul64(_a: u64, _b: u64) -> u128 {
    unreachable!("no carry-less multiply back end on this architecture")
}

/// A GHASH subkey readied for the hardware multiply ([`mulx_POLYVAL`]
/// applied once, instead of redoing it on every block).
///
/// There is no constructor but [`prepare`], which is what makes
/// [`mul`](Self::mul) sound: no value of this type exists unless the CPU
/// support was there when it was built.
///
/// [`mulx_POLYVAL`]: https://www.rfc-editor.org/rfc/rfc8452#appendix-A
pub struct PreparedKey(u128);

impl PreparedKey {
    /// `x · H` over the GHASH field, for the `H` this key was prepared from.
    #[inline]
    pub fn mul(&self, x: u128) -> u128 {
        // Safety: `PreparedKey` is only ever built by `prepare`, which
        // returned `Some` only after `available()` said the instructions
        // exist on this CPU; that cannot regress at runtime.
        unsafe { dot(x, self.0) }
    }
}

/// Prepare the GHASH subkey `E(K, 0^128)` (a big-endian `u128`) for
/// [`PreparedKey::mul`]; `None` when the CPU has no carry-less multiply.
pub fn prepare(h: u128) -> Option<PreparedKey> {
    if available() {
        Some(PreparedKey(mulx(h)))
    } else {
        None
    }
}

/// The `mulX_POLYVAL()` doubling from RFC 8452 Appendix A.
///
/// `v` is the GHASH key as the POLYVAL core reads it — the little-endian
/// value of the key block's bytes, which for a key carried as a big-endian
/// `u128` is that same `u128`. The result is in the same convention.
fn mulx(v: u128) -> u128 {
    let carry = v >> 127;
    let doubled = v << 1;
    doubled ^ carry ^ (carry << 127) ^ (carry << 126) ^ (carry << 121)
}

/// Shift each 64-bit lane of `v` right by `n` (no bits cross the lane
/// boundary) — `_mm_srli_epi64` / `vshrq_n_u64` semantics.
#[inline]
fn lane_sr(v: u128, n: u32) -> u128 {
    let lo = (v as u64) >> n;
    let hi = ((v >> 64) as u64) >> n;
    ((hi as u128) << 64) | (lo as u128)
}

/// Shift each 64-bit lane of `v` left by `n` — `_mm_slli_epi64` semantics.
#[inline]
fn lane_sl(v: u128, n: u32) -> u128 {
    let lo = (v as u64) << n;
    let hi = ((v >> 64) as u64) << n;
    ((hi as u128) << 64) | (lo as u128)
}

/// One carry-less multiply-and-reduce: `x · h` in POLYVAL's terms.
///
/// This is the RustCrypto `polyval` `CLMUL` sequence translated step for
/// step into scalar arithmetic — its SIMD shifts are per-lane, so the lane
/// helpers above reproduce them exactly, and the final result's low lane
/// depends on low lanes only (the reference discards the top lane with
/// `_mm_unpacklo_epi64` for the same reason). The agreement test against the
/// software multiply in [`aes_gcm`](super::aes_gcm) is what proves the
/// translation, on hardware that can execute both.
///
/// # Safety
/// The CPU must implement the carry-less multiply instructions.
#[inline]
unsafe fn dot(x: u128, h: u128) -> u128 {
    let (x0, x1) = (x as u64, (x >> 64) as u64);
    let (h0, h1) = (h as u64, (h >> 64) as u64);

    // Karatsuba: three 64×64 products cover the 128×128 one.
    let t0 = clmul64(x0, h0);
    let t1 = clmul64(x1, h1);
    let t2 = clmul64(x0 ^ x1, h0 ^ h1) ^ t0 ^ t1;

    let v0 = t0;
    let v1 = (t0 >> 64) ^ t2;
    let v2 = t1 ^ (t2 >> 64);
    let v3 = t1 >> 64;

    // Reduction: fold the high half back in with the shifts POLYVAL's
    // polynomial was chosen for (57..63 bits, twice).
    let v2 = v2 ^ v0 ^ lane_sr(v0, 1) ^ lane_sr(v0, 2) ^ lane_sr(v0, 7);
    let v1 = v1 ^ lane_sl(v0, 63) ^ lane_sl(v0, 62) ^ lane_sl(v0, 57);
    let v3 = v3 ^ v1 ^ lane_sr(v1, 1) ^ lane_sr(v1, 2) ^ lane_sr(v1, 7);
    let v2 = v2 ^ lane_sl(v1, 63) ^ lane_sl(v1, 62) ^ lane_sl(v1, 57);

    let low_lane = 0xffff_ffff_ffff_ffffu128;
    (v2 & low_lane) | ((v3 & low_lane) << 64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex16(text: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("hex");
        }
        out
    }

    /// RFC 8452 Appendix A's `mulX_POLYVAL` vector (with the published
    /// erratum applied — the value the reference crate tests against).
    #[test]
    fn mulx_follows_rfc_8452() {
        let input = u128::from_le_bytes(hex16("9c98c04df9387ded828175a92ba652d8"));
        let expected = u128::from_le_bytes(hex16("3931819bf271fada0503eb52574ca572"));
        assert_eq!(mulx(input), expected);
    }

    /// Doubling a root of the polynomial wraps with the RFC's constants:
    /// `1 << 127` doubles to `1 ^ (1<<127) ^ (1<<126) ^ (1<<121)`, i.e. the
    /// polynomial itself with the leading term cancelled.
    #[test]
    fn mulx_wraps_at_the_top() {
        let wrapped = mulx(1u128 << 127);
        assert_eq!(
            wrapped,
            1 ^ (1u128 << 127) ^ (1u128 << 126) ^ (1u128 << 121)
        );
    }
}
