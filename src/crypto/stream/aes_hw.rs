//! AES round hardware: AES-NI (x86/x86_64) and the ARMv8 AES instructions
//! (aarch64).
//!
//! Every AES consumer in the engine — GCM's counter blocks, CFB128, CTR,
//! CBC and VMess's raw ECB block — funnels through
//! [`Aes::encrypt_block`](super::aes::Aes::encrypt_block) /
//! [`decrypt_block`](super::aes::Aes::decrypt_block), so replacing the round
//! function here accelerates all of them at once; there is no second AES
//! anywhere in the crate.
//!
//! What is *not* replaced is the key schedule: it stays in the software
//! implementation — it is the FIPS 197 reference, verified by the Appendix C
//! vectors, and both instruction sets consume exactly those round keys. The
//! x86 sequence is the textbook `AESENC`/`AESDEC` one; the ARMv8 sequence
//! accounts for `AESE`/`AESD` XORing their round key *before* SubBytes (see
//! `arm::encrypt_block`).
//!
//! # Availability
//!
//! * `target_feature = "aes"` (the crate was compiled for a CPU that has
//!   it, e.g. `-C target-cpu=native`): always used;
//! * x86/x86_64: one CPUID leaf-1 probe — `ECX.AESNI` (bit 25) plus
//!   `EDX.SSE` and `EDX.FXSR`, so a CPU running under an OS that does not
//!   save the XMM state is excluded. This is probeable without `std`;
//! * aarch64 with `std`: `is_aarch64_feature_detected!("aes")` (HWCAP);
//! * aarch64 without `std` and without the compile-time feature: the
//!   software path. There is no portable HWCAP read outside `std`, and
//!   reading it behind the kernel's back is not a shortcut worth taking.
//!
//! Detection is cached in a relaxed atomic and consulted again by the safe
//! round wrappers at the bottom of this file — a relaxed load is noise next
//! to the rounds it guards, and it keeps every caller, including
//! [`Aes`](super::aes::Aes), free of `unsafe`.
//!
//! # Safety
//!
//! This module is one of the crate's four audited `unsafe` sites — the
//! others are `common::roots`, `common::socket` and `crypto::aead::ghash_hw`
//! (the GHASH carry-less multiply); the list lives in `common`. It is
//! reached from `crypto`, which itself is `#![deny(unsafe_code)]`. The
//! unsafe surface is exactly:
//!
//! 1. the CPUID / HWCAP probe (architectural, read-only);
//! 2. the per-architecture round functions, each
//!    `#[target_feature(enable = "aes")]` and `unsafe`, reachable only
//!    through the wrappers at the bottom of this file — an
//!    `if !available() { return false; }` away from the intrinsics;
//!    nothing outside this file names them;
//! 3. unaligned vector loads/stores over fixed-size arrays (`loadu`/
//!    `storeu` on x86, `vld1q`/`vst1q` on ARM), which accept any alignment
//!    by definition.
//!
//! No other module may call the intrinsics, and nothing here reads or writes
//! memory outside the round-key array and the caller's 16-byte block.

#![allow(unsafe_code)]

// ---------------------------------------------------------------------------
// x86 / x86_64 — AES-NI
// ---------------------------------------------------------------------------

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86 {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::{
        __cpuid, __m128i, _mm_aesdec_si128, _mm_aesdeclast_si128, _mm_aesenc_si128,
        _mm_aesenclast_si128, _mm_aesimc_si128, _mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128,
    };
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::{
        __cpuid, __m128i, _mm_aesdec_si128, _mm_aesdeclast_si128, _mm_aesenc_si128,
        _mm_aesenclast_si128, _mm_aesimc_si128, _mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128,
    };
    use core::sync::atomic::{AtomicU8, Ordering};

    /// `0` unknown, `1` absent, `2` present.
    static AVAILABLE: AtomicU8 = AtomicU8::new(0);

    /// Whether AES-NI may be executed on this CPU (and this OS keeps XMM
    /// state across context switches).
    pub fn available() -> bool {
        if cfg!(target_feature = "aes") {
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
                /// CPUID.1:ECX[25] — AES-NI.
                const AESNI: u32 = 1 << 25;
                /// CPUID.1:EDX[25] — SSE.
                const SSE: u32 = 1 << 25;
                /// CPUID.1:EDX[24] — FXSAVE/FXRSTOR (the OS saves XMM state).
                const FXSR: u32 = 1 << 24;
                let present = leaf.ecx & AESNI != 0 && leaf.edx & (SSE | FXSR) == (SSE | FXSR);
                AVAILABLE.store(if present { 2 } else { 1 }, Ordering::Relaxed);
                present
            }
        }
    }

    /// Round key `round` as a vector. `keys` always holds `rounds + 1`
    /// blocks, so the index is in bounds; `loadu` takes any alignment.
    #[inline]
    fn round_key(keys: &[[u8; 16]], round: usize) -> __m128i {
        unsafe { _mm_loadu_si128(keys.as_ptr().add(round) as *const __m128i) }
    }

    /// Encrypt one block: `state = AESENC(·, rk[0..rounds])`, with the final
    /// round using `AESENCLAST` (no MixColumns) — FIPS 197 §5.1.
    ///
    /// [`available`] must have returned `true` on this CPU; `keys` must hold
    /// `rounds + 1` blocks.
    #[target_feature(enable = "aes")]
    pub unsafe fn encrypt_block(rounds: usize, keys: &[[u8; 16]], block: &mut [u8; 16]) {
        let mut state = round_key(keys, 0);
        state = _mm_xor_si128(state, _mm_loadu_si128(block.as_ptr() as *const __m128i));
        for round in 1..rounds {
            state = _mm_aesenc_si128(state, round_key(keys, round));
        }
        state = _mm_aesenclast_si128(state, round_key(keys, rounds));
        _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
    }

    /// Decrypt one block. The equivalent-inverse trick: `AESDEC` with
    /// `AESIMC(rk[i])` evaluates `InvMixColumns(InvSubBytes(InvShiftRows(s))
    /// ⊕ rk[i])`, which is exactly the FIPS 197 §5.3 inverse round, and
    /// `AESDECLAST` with `rk[0]` is the final one.
    ///
    /// Same contract as [`encrypt_block`].
    #[target_feature(enable = "aes")]
    pub unsafe fn decrypt_block(rounds: usize, keys: &[[u8; 16]], block: &mut [u8; 16]) {
        let mut state = _mm_xor_si128(
            _mm_loadu_si128(block.as_ptr() as *const __m128i),
            round_key(keys, rounds),
        );
        for round in (1..rounds).rev() {
            state = _mm_aesdec_si128(state, _mm_aesimc_si128(round_key(keys, round)));
        }
        state = _mm_aesdeclast_si128(state, round_key(keys, 0));
        _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
    }
}

// ---------------------------------------------------------------------------
// aarch64 — the ARMv8 AES instructions
// ---------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
mod arm {
    use core::arch::aarch64::{
        uint8x16_t, vaesdq_u8, vaeseq_u8, vaesimcq_u8, vaesmcq_u8, veorq_u8, vld1q_u8, vst1q_u8,
    };

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
                let present = std::arch::is_aarch64_feature_detected!("aes");
                AVAILABLE.store(if present { 2 } else { 1 }, Ordering::Relaxed);
                present
            }
        }
    }

    /// Without `std` there is no portable HWCAP read: the software rounds
    /// (or a compile-time `aes` target feature) are all that is left.
    #[cfg(not(feature = "std"))]
    fn detected() -> bool {
        false
    }

    /// Whether the CPU implements the ARMv8 AES instructions.
    pub fn available() -> bool {
        cfg!(target_feature = "aes") || detected()
    }

    /// Round key `round` as a vector. `vld1q` is an unaligned load.
    #[inline]
    fn round_key(keys: &[[u8; 16]], round: usize) -> uint8x16_t {
        unsafe { vld1q_u8(keys.as_ptr().add(round) as *const u8) }
    }

    /// Encrypt one block.
    ///
    /// `AESE(s, k)` is `ShiftRows(SubBytes(s ⊕ k))` — the ARM instructions
    /// add the round key *first*, unlike `AESENC` — and `AESMC` is
    /// MixColumns. The canonical ARMv8 sequence with plain FIPS round keys
    /// is therefore one key away from the x86 shape: `rounds - 1`
    /// `AESE`+`AESMC` pairs over `rk[0..rounds-1]`, then a bare `AESE` with
    /// `rk[rounds-1]` and an explicit XOR of `rk[rounds]`, which together do
    /// what `AESENCLAST` does (the intermediate states deliberately carry
    /// the next round key — `AESE`'s early XOR is what cancels it again).
    ///
    /// [`available`] must have returned `true` on this CPU; `keys` must hold
    /// `rounds + 1` blocks.
    #[target_feature(enable = "aes")]
    pub unsafe fn encrypt_block(rounds: usize, keys: &[[u8; 16]], block: &mut [u8; 16]) {
        let mut state = vld1q_u8(block.as_ptr());
        for round in 0..rounds - 1 {
            state = vaesmcq_u8(vaeseq_u8(state, round_key(keys, round)));
        }
        state = vaeseq_u8(state, round_key(keys, rounds - 1));
        state = veorq_u8(state, round_key(keys, rounds));
        vst1q_u8(block.as_mut_ptr(), state);
    }

    /// Decrypt one block.
    ///
    /// The ARMv8 form of the FIPS 197 equivalent inverse cipher: `AESD` is
    /// `InvShiftRows(InvSubBytes(s ⊕ k))` (key first, like `AESE`) and
    /// `AESIMC` is InvMixColumns. The keys are consumed in reverse with
    /// InvMixColumns folded in — `dk[0] = rk[rounds]` raw,
    /// `dk[i] = AESIMC(rk[rounds-i])` for `i = 1..=rounds-1` — each
    /// `AESIMC` cancelling the key XOR the previous `AESD` left in the
    /// register, exactly as the encrypt side runs one key ahead. The final
    /// step is a bare `AESD` with `dk[rounds-1] = AESIMC(rk[1])` and an
    /// explicit XOR of `rk[0]`.
    ///
    /// Same contract as [`encrypt_block`].
    #[target_feature(enable = "aes")]
    pub unsafe fn decrypt_block(rounds: usize, keys: &[[u8; 16]], block: &mut [u8; 16]) {
        let mut state = vld1q_u8(block.as_ptr());
        state = vaesimcq_u8(vaesdq_u8(state, round_key(keys, rounds)));
        for round in (2..rounds).rev() {
            state = vaesimcq_u8(vaesdq_u8(state, vaesimcq_u8(round_key(keys, round))));
        }
        state = vaesdq_u8(state, vaesimcq_u8(round_key(keys, 1)));
        state = veorq_u8(state, round_key(keys, 0));
        vst1q_u8(block.as_mut_ptr(), state);
    }
}

#[cfg(target_arch = "aarch64")]
use arm as back_end;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86 as back_end;

/// Whether the platform's AES round instructions are usable on this CPU.
///
/// Architectures without a back end always answer `false`, which is what
/// sends [`Aes`](super::aes::Aes) down the software path.
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
pub fn available() -> bool {
    back_end::available()
}

/// Architectures without a hardware AES back end: the software rounds in
/// [`Aes`](super::aes::Aes) are the only implementation, so nothing is
/// available here.
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
pub fn available() -> bool {
    false
}

/// Encrypt one block with the hardware rounds, returning `false` (block and
/// keys untouched) when the CPU has no AES instructions.
///
/// This is the only encryption entry point callers such as
/// [`Aes`](super::aes::Aes) reach; the runtime check keeps the `unsafe`
/// call out of their code.
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
pub fn encrypt_block(rounds: usize, keys: &[[u8; 16]], block: &mut [u8; 16]) -> bool {
    if !available() {
        return false;
    }
    unsafe { back_end::encrypt_block(rounds, keys, block) };
    true
}

/// Decrypt one block with the hardware rounds; contract as
/// [`encrypt_block`].
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
pub fn decrypt_block(rounds: usize, keys: &[[u8; 16]], block: &mut [u8; 16]) -> bool {
    if !available() {
        return false;
    }
    // Safety: as in `encrypt_block`.
    unsafe { back_end::decrypt_block(rounds, keys, block) };
    true
}
