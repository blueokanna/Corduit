//! AES-GCM authenticated encryption (NIST SP 800-38D).
//!
//! The 12-byte nonce (what every consumer in Corduit uses) takes the direct
//! `J0 = nonce ‖ 0^31 ‖ 1` path; any other non-empty length goes through the
//! GHASH fallback of SP 800-38D §7.1.
//!
//! The GHASH field multiply runs on the CPU's carry-less multiply
//! instructions when it has them ([`ghash_hw`]: `PCLMULQDQ` / `PMULL`); the
//! software multiply below is the fallback and takes both operands as
//! arithmetic masks — branch-free, nothing indexed by secrets.

use super::ghash_hw;
use crate::crypto::aead::{AeadError, AeadInPlace};
use crate::crypto::stream::Aes;
use crate::crypto::util::ct_eq;

/// Reduction polynomial of GF(2^128) for GHASH: x^128 + x^7 + x^2 + x + 1.
const R: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;

/// Multiplication in GF(2^128): the fallback used when the CPU has no
/// carry-less multiply (see [`ghash_hw`]), and the oracle the hardware path
/// is tested against. Branch-free — every bit decision becomes a mask.
///
/// Implements the canonical GCM bit-string multiplication (NIST
/// SP 800-38D §6.3): Y is consumed most-significant bit first and V is
/// shifted right, folding the reduction polynomial
/// `x^128 + x^7 + x^2 + x + 1` via `R = 0xe1 || 0^120` whenever the
/// outgoing (least-significant) bit of V is set.
fn gf_mul(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut x = x;
    let mut y = y;
    for _ in 0..128 {
        // Each bit becomes a 0/all-ones mask, so neither the secret `H`
        // (riding in `x`) nor a secret intermediate (in `y`) is ever the
        // subject of a branch the hardware can predict or time.
        let bit = ((y >> 127) & 1).wrapping_neg();
        z ^= x & bit;
        y <<= 1;
        let low = (x & 1).wrapping_neg();
        x = (x >> 1) ^ (R & low);
    }
    z
}

/// Increment the low 32 bits of a GCM counter block.
fn inc32(counter: u128) -> u128 {
    let low = (counter & 0xffff_ffff).wrapping_add(1) & 0xffff_ffff;
    (counter & !0xffff_ffffu128) | low
}

/// Streaming GHASH accumulator (AAD then ciphertext).
struct GHash {
    h: u128,
    /// The same key readied for the hardware carry-less multiply, when the
    /// CPU has it; `None` keeps every multiply on [`gf_mul`].
    hw: Option<ghash_hw::PreparedKey>,
    state: u128,
    buf: [u8; 16],
    buf_len: usize,
    aad_len: u64,
    ct_len: u64,
    phase: u8,
}

impl GHash {
    /// A GHASH that uses the hardware multiply only when `hardware` allows
    /// it (still subject to CPU detection); `false` keeps every multiply on
    /// [`gf_mul`]. The tests use `false` to run the same data through both
    /// implementations.
    fn with_backend(h: u128, hardware: bool) -> Self {
        GHash {
            h,
            hw: if hardware { ghash_hw::prepare(h) } else { None },
            state: 0,
            buf: [0u8; 16],
            buf_len: 0,
            aad_len: 0,
            ct_len: 0,
            phase: 0,
        }
    }

    /// The one place a block is multiplied by `H`, on whichever back end
    /// this accumulator was built with.
    #[inline]
    fn mul(&self, x: u128) -> u128 {
        match &self.hw {
            Some(prepared) => prepared.mul(x),
            None => gf_mul(x, self.h),
        }
    }

    fn absorb_block(&mut self, block: &[u8; 16]) {
        // GCM treats 128-bit blocks as big-endian bit strings (the first
        // byte is the coefficient of x^127).
        let x = u128::from_be_bytes(*block);
        self.state = self.mul(self.state ^ x);
    }

    fn push(&mut self, mut data: &[u8]) {
        if self.phase == 0 {
            self.aad_len = self.aad_len.wrapping_add(data.len() as u64);
        } else {
            self.ct_len = self.ct_len.wrapping_add(data.len() as u64);
        }

        if self.buf_len != 0 {
            let want = 16 - self.buf_len;
            let take = want.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 16 {
                let full = self.buf;
                self.absorb_block(&full);
                self.buf_len = 0;
            }
        }

        while data.len() >= 16 {
            let block: [u8; 16] = data[..16].try_into().expect("16");
            self.absorb_block(&block);
            data = &data[16..];
        }

        // `push` is a stream: a call may leave a partial block for the next
        // one. Only copy what arrived and add to the fill count — assigning
        // `data.len()` would silently discard a block filled by an earlier
        // call when the new data does not complete it.
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
        }
        self.buf_len += data.len();
    }

    /// Zero-pad the current partial block (if any) and absorb it.
    ///
    /// GCM interleaves AAD and ciphertext through a single padded stream:
    /// `aad || pad16(aad) || ct || pad16(ct)`. This must be called between
    /// the AAD and the ciphertext so the AAD padding is consumed before any
    /// ciphertext bytes are absorbed.
    fn pad_to_block(&mut self) {
        if self.buf_len > 0 {
            // Zero-pad the filled prefix explicitly; the tail of `self.buf`
            // may hold stale bytes from an earlier partial block when callers
            // push in pieces, and GHASH must only see the new bytes.
            let mut block = [0u8; 16];
            block[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            self.absorb_block(&block);
            self.buf_len = 0;
            self.buf = [0u8; 16];
        }
    }

    /// Finalize: zero-pad the partial block, append the 128-bit length block
    /// and return S. (GCM pads partial blocks with zeros, not 0x80.)
    ///
    /// The length block carries the *bit* lengths of the AAD and the
    /// ciphertext, each as a big-endian 64-bit integer.
    fn finalize(mut self) -> u128 {
        if self.buf_len > 0 {
            let mut block = [0u8; 16];
            block[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            let x = u128::from_be_bytes(block);
            self.state = self.mul(self.state ^ x);
        }
        let lb = (((self.aad_len as u128) << 3) << 64) | ((self.ct_len as u128) << 3);
        self.absorb_block(&lb.to_be_bytes());
        self.state
    }
}

/// AES-GCM cipher for a fixed key size.
pub struct AesGcm {
    cipher: Aes,
    /// Whether GHASH may use the carry-less multiply instructions. Kept on
    /// the cipher because `j0`'s GHASH fallback (a non-12-byte nonce) needs
    /// the same decision outside of a [`GHash`].
    hw_ghash: bool,
}

impl AesGcm {
    /// Create from a 16/24/32-byte key.
    pub fn new(key: &[u8]) -> Result<Self, crate::crypto::InvalidLength> {
        Self::with_backend(key, true)
    }

    /// As [`AesGcm::new`], gating the hardware GHASH on `hardware` (still
    /// subject to CPU detection). The tests use `false` to run the same
    /// vectors through both implementations.
    fn with_backend(key: &[u8], hardware: bool) -> Result<Self, crate::crypto::InvalidLength> {
        Ok(AesGcm {
            cipher: Aes::new(key)?,
            hw_ghash: hardware && ghash_hw::available(),
        })
    }

    /// Alias of [`AesGcm::new`] for compatibility with the `aead` crate
    /// call sites.
    pub fn new_from_slice(key: &[u8]) -> Result<Self, crate::crypto::InvalidLength> {
        Self::new(key)
    }

    #[inline]
    fn h(&self) -> u128 {
        let mut block = [0u8; 16];
        self.cipher.encrypt_block(&mut block);
        u128::from_be_bytes(block)
    }

    fn j0(&self, nonce: &[u8]) -> Result<u128, AeadError> {
        if nonce.len() == 12 {
            let mut j0 = [0u8; 16];
            j0[..12].copy_from_slice(nonce);
            j0[15] = 1;
            Ok(u128::from_be_bytes(j0))
        } else {
            if nonce.is_empty() {
                return Err(AeadError::InvalidNonceLength);
            }
            let h = self.h();
            let prepared = if self.hw_ghash {
                ghash_hw::prepare(h)
            } else {
                None
            };
            let mul = |x: u128| match &prepared {
                Some(prepared) => prepared.mul(x),
                None => gf_mul(x, h),
            };
            let mut state = 0u128;
            let mut blocks = nonce.chunks_exact(16);
            for block in &mut blocks {
                let arr: [u8; 16] = block.try_into().unwrap();
                state = mul(state ^ u128::from_be_bytes(arr));
            }
            let rem = blocks.remainder();
            if !rem.is_empty() {
                let mut block = [0u8; 16];
                block[..rem.len()].copy_from_slice(rem);
                state = mul(state ^ u128::from_be_bytes(block));
            }
            let mut lb = [0u8; 16];
            lb[8..].copy_from_slice(&((nonce.len() as u64) * 8).to_be_bytes());
            state = mul(state ^ u128::from_be_bytes(lb));
            Ok(state)
        }
    }

    fn ctr_crypt(&self, icb: u128, buffer: &mut [u8]) {
        let mut counter = inc32(icb);
        let mut block = [0u8; 16];
        for chunk in buffer.chunks_mut(16) {
            block.copy_from_slice(&counter.to_be_bytes());
            self.cipher.encrypt_block(&mut block);
            for (dst, src) in chunk.iter_mut().zip(block.iter()) {
                *dst ^= src;
            }
            counter = inc32(counter);
        }
    }
}

impl AeadInPlace for AesGcm {
    fn encrypt_in_place_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), AeadError> {
        let j0 = self.j0(nonce)?;
        let h = self.h();
        self.ctr_crypt(j0, buffer);

        let s = {
            let mut g = GHash::with_backend(h, self.hw_ghash);
            g.push(aad);
            g.pad_to_block();
            g.phase = 1;
            g.push(buffer);
            g.finalize()
        };
        let mut j0b = [0u8; 16];
        j0b.copy_from_slice(&j0.to_be_bytes());
        self.cipher.encrypt_block(&mut j0b);
        let ek = u128::from_be_bytes(j0b);
        tag.copy_from_slice(&(ek ^ s).to_be_bytes());
        Ok(())
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), AeadError> {
        let j0 = self.j0(nonce)?;
        let h = self.h();

        // Compute the tag over the ciphertext first (constant-time check
        // before any plaintext is released).
        let s = {
            let mut g = GHash::with_backend(h, self.hw_ghash);
            g.push(aad);
            g.pad_to_block();
            g.phase = 1;
            g.push(buffer);
            g.finalize()
        };
        let mut j0b = [0u8; 16];
        j0b.copy_from_slice(&j0.to_be_bytes());
        self.cipher.encrypt_block(&mut j0b);
        let ek = u128::from_be_bytes(j0b);

        let mut expected = [0u8; 16];
        expected.copy_from_slice(&(ek ^ s).to_be_bytes());
        if tag.len() != 16 || !ct_eq(&expected, tag) {
            // Wipe the buffer so no unauthenticated data escapes.
            crate::crypto::util::zeroize(buffer);
            return Err(AeadError::AuthenticationFailed);
        }

        self.ctr_crypt(j0, buffer);
        Ok(())
    }
}

macro_rules! define_aes_gcm {
    ($name:ident, $keylen:expr) => {
        /// AES-GCM with a fixed key size.
        pub struct $name {
            inner: AesGcm,
        }

        impl $name {
            /// Create from a `$keylen`-byte key.
            pub fn new(key: &[u8; $keylen]) -> Self {
                $name {
                    inner: AesGcm::new(key).expect("key length validated by type"),
                }
            }

            /// Create from a slice, validating the length.
            pub fn new_from_slice(key: &[u8]) -> Result<Self, crate::crypto::InvalidLength> {
                if key.len() != $keylen {
                    return Err(crate::crypto::InvalidLength);
                }
                Ok($name {
                    inner: AesGcm::new(key).expect("key length validated"),
                })
            }
        }

        impl AeadInPlace for $name {
            fn encrypt_in_place_detached(
                &self,
                nonce: &[u8],
                aad: &[u8],
                buffer: &mut [u8],
                tag: &mut [u8; 16],
            ) -> Result<(), AeadError> {
                self.inner
                    .encrypt_in_place_detached(nonce, aad, buffer, tag)
            }

            fn decrypt_in_place_detached(
                &self,
                nonce: &[u8],
                aad: &[u8],
                buffer: &mut [u8],
                tag: &[u8],
            ) -> Result<(), AeadError> {
                self.inner
                    .decrypt_in_place_detached(nonce, aad, buffer, tag)
            }
        }
    };
}

define_aes_gcm!(Aes128Gcm, 16);
define_aes_gcm!(Aes192Gcm, 24);
define_aes_gcm!(Aes256Gcm, 32);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::AeadInPlace;

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn encrypt_vec(cipher: &AesGcm, nonce: &[u8], aad: &[u8], pt: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let mut buf = pt.to_vec();
        let mut tag = [0u8; 16];
        cipher
            .encrypt_in_place_detached(nonce, aad, &mut buf, &mut tag)
            .unwrap();
        (buf, tag)
    }

    /// GHASH is a stream: feeding the same bytes in different chunks must
    /// produce the same tag. The regression is the call that ends mid-block
    /// after an earlier call already filled part of that block.
    #[test]
    fn ghash_push_is_chunk_agnostic() {
        let h = 0x66e94bd4ef8a2c3b884cfa59ca342b2eu128;
        let data: Vec<u8> = (0..37u8).collect();

        let mut whole = GHash::with_backend(h, true);
        whole.push(&data);

        let mut split = GHash::with_backend(h, true);
        split.push(&data[..5]);
        split.push(&data[5..8]);
        split.push(&data[8..]);

        assert_eq!(whole.finalize(), split.finalize());
    }

    #[test]
    fn nist_gcm_vectors() {
        // NIST GCM test vectors (McGrew & Viega), AES-128.
        // Case 1: empty AAD & plaintext, all-zero key & nonce.
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let cipher = AesGcm::new(&key).unwrap();
        let (ct, tag) = encrypt_vec(&cipher, &nonce, &[], &[]);
        assert!(ct.is_empty());
        assert_eq!(hex(&tag), "58e2fccefa7e3061367f1d57a4e7455a");

        // NIST AES-128 GCM vector: key all-zero, nonce all-zero, pt 0^16.
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let pt = [0u8; 16];
        let cipher = AesGcm::new(&key).unwrap();
        let (ct, tag) = encrypt_vec(&cipher, &nonce, &[], &pt);
        assert_eq!(hex(&ct), "0388dace60b6a392f328c2b971b2fe78");
        assert_eq!(hex(&tag), "ab6e47d42cec13bdf53a67b21257bddf");
    }

    #[test]
    fn nist_gcm_case3_with_aad() {
        // McGrew & Viega AES-128 GCM, test case 3 (exercises AAD + 3 blocks).
        // Expected values cross-checked against the reference `aes-gcm` crate.
        let key = unhex("feffe9928665731c6d6a8f9467308308");
        let nonce = unhex("cafebabefacedbaddecaf888");
        let aad = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let pt = unhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        let cipher = AesGcm::new(&key).unwrap();
        let (ct, tag) = encrypt_vec(&cipher, &nonce, &aad, &pt);
        assert_eq!(
            hex(&ct),
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
        );
        assert_eq!(hex(&tag), "5bc94fbc3221a5db94fae95ae7121a47");

        // Decrypt round-trips with the same AAD.
        let mut buf = ct.clone();
        cipher
            .decrypt_in_place_detached(&nonce, &aad, &mut buf, &tag)
            .unwrap();
        assert_eq!(buf, pt);
    }

    #[test]
    fn roundtrip_with_aad() {
        let key = [0x11u8; 16];
        let nonce = [0x22u8; 12];
        let aad = b"associated data";
        let pt = b"the quick brown fox";
        let cipher = AesGcm::new(&key).unwrap();

        let (ct, tag) = encrypt_vec(&cipher, &nonce, aad, pt);
        assert_ne!(&ct, &pt[..]);

        let mut buf = ct.clone();
        cipher
            .decrypt_in_place_detached(&nonce, aad, &mut buf, &tag)
            .unwrap();
        assert_eq!(&buf, pt);

        // Tamper: wrong tag must fail and not leak.
        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        let mut buf = ct.clone();
        assert_eq!(
            cipher.decrypt_in_place_detached(&nonce, aad, &mut buf, &bad_tag),
            Err(AeadError::AuthenticationFailed)
        );
        // Wrong AAD must fail too.
        let mut buf = ct.clone();
        assert_eq!(
            cipher.decrypt_in_place_detached(&nonce, b"other", &mut buf, &tag),
            Err(AeadError::AuthenticationFailed)
        );
    }

    #[test]
    fn ghash_known_answers() {
        // RFC 8452 Appendix A GHASH vector (same vector the `ghash` crate
        // uses in its own test suite): GHASH(H, X1, X2).
        let h = 0x2562_9347_5892_4276_1d31_f826_ba4b_757b;
        let x1 = 0x4f4f_9566_8c83_dfb6_4017_62bb_2d01_a262;
        let x2 = 0xd1a2_4ddd_2721_d006_bbe4_5f20_d3c9_f362;
        assert_eq!(
            gf_mul(gf_mul(x1, h) ^ x2, h),
            0xbd9b_3997_0467_31fb_9625_1b91_f9c9_9d7a
        );
        // Zero element annihilates.
        assert_eq!(gf_mul(0, 0x1234_5678_9abc_def0), 0);
        // The multiplicative identity: 1 = 2^127 in this representation.
        assert_eq!(
            gf_mul(1u128 << 127, 0xdead_beef_1234_5678_9abc_def0_1234_5678),
            0xdead_beef_1234_5678_9abc_def0_1234_5678
        );
    }

    #[test]
    fn non_standard_nonce_len() {
        // 8-byte nonce must work and round-trip.
        let key = [7u8; 32];
        let nonce = [0xabu8; 8];
        let cipher = AesGcm::new(&key).unwrap();
        let pt = b"data";
        let (ct, tag) = encrypt_vec(&cipher, &nonce, b"aad", pt);
        let mut buf = ct.clone();
        cipher
            .decrypt_in_place_detached(&nonce, b"aad", &mut buf, &tag)
            .unwrap();
        assert_eq!(&buf, pt);
    }

    /// Every hardware multiply must equal the software one bit for bit: the
    /// hardware path is three carry-less multiplies plus a fixed reduction,
    /// and this pins down the whole mapping — the `mulx` key transform, the
    /// POLYVAL core, the absent byte-order conversions — over the field's
    /// edge values and a deterministic spread of others.
    #[test]
    fn hardware_ghash_matches_the_software_multiply() {
        if !ghash_hw::available() {
            return;
        }
        let mut seed = 0x243f_6a88_85a3_08d3_1319_8a2e_0370_7344u128;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut values = vec![
            0,
            1,
            u128::MAX,
            1u128 << 127, // the field's one
            0xe100_0000_0000_0000_0000_0000_0000_0000,
            0x2562_9347_5892_4276_1d31_f826_ba4b_757b, // RFC 8452's H
            0x66e9_4bd4_ef8a_2c3b_884c_fa59_ca34_2b2e, // NIST's H
        ];
        for _ in 0..25 {
            values.push(next());
        }
        for &h in &values {
            let prepared = ghash_hw::prepare(h).expect("available() was true");
            for &x in &values {
                assert_eq!(prepared.mul(x), gf_mul(x, h), "h={h:032x} x={x:032x}");
            }
        }
    }

    /// Both GHASH back ends must fold the same stream to the same `S`.
    #[test]
    fn ghash_backends_agree_on_one_stream() {
        let h = 0x66e9_4bd4_ef8a_2c3b_884c_fa59_ca34_2b2eu128;
        let aad = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let ct: Vec<u8> = (0..61u8)
            .map(|i| i.wrapping_mul(7).wrapping_add(3))
            .collect();

        let mut hardware = GHash::with_backend(h, true);
        let mut software = GHash::with_backend(h, false);
        for g in [&mut hardware, &mut software] {
            g.push(&aad);
            g.pad_to_block();
            g.phase = 1;
            g.push(&ct);
        }
        assert_eq!(hardware.finalize(), software.finalize());
    }

    /// The whole cipher — counter blocks, `j0`'s GHASH fallback for a
    /// non-12-byte nonce, the tag — must be identical on both GHASH back
    /// ends, and a message sealed by one must open under the other.
    #[test]
    fn aes_gcm_backends_agree_end_to_end() {
        let key = unhex("feffe9928665731c6d6a8f9467308308");
        let aad = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let pt: Vec<u8> = (0..75u8)
            .map(|i| i.wrapping_mul(3).wrapping_add(1))
            .collect();

        let hardware = AesGcm::with_backend(&key, true).unwrap();
        let software = AesGcm::with_backend(&key, false).unwrap();
        assert_eq!(hardware.hw_ghash, ghash_hw::available());

        let empty: [u8; 0] = [];
        let mut nothing = Vec::new();
        assert_eq!(
            hardware.encrypt_in_place_detached(&empty, &aad, &mut nothing, &mut [0u8; 16]),
            Err(AeadError::InvalidNonceLength)
        );

        for nonce in [
            unhex("cafebabefacedbaddecaf888"), // 12 bytes: direct `j0`
            unhex("aabbccddeeff00112233"),     // 10 bytes: GHASH-fallback `j0`
        ] {
            let mut hw_buf = pt.clone();
            let mut hw_tag = [0u8; 16];
            hardware
                .encrypt_in_place_detached(&nonce, &aad, &mut hw_buf, &mut hw_tag)
                .unwrap();
            let mut sw_buf = pt.clone();
            let mut sw_tag = [0u8; 16];
            software
                .encrypt_in_place_detached(&nonce, &aad, &mut sw_buf, &mut sw_tag)
                .unwrap();
            assert_eq!(hw_buf, sw_buf, "ciphertext for nonce {nonce:02x?}");
            assert_eq!(hw_tag, sw_tag, "tag for nonce {nonce:02x?}");

            // The two ends interoperate: software opens what hardware sealed,
            // and vice versa.
            let mut opened = hw_buf.clone();
            software
                .decrypt_in_place_detached(&nonce, &aad, &mut opened, &hw_tag)
                .unwrap();
            assert_eq!(opened, pt);
            let mut opened = sw_buf.clone();
            hardware
                .decrypt_in_place_detached(&nonce, &aad, &mut opened, &sw_tag)
                .unwrap();
            assert_eq!(opened, pt);
        }
    }
}
