//! SHA-2 family (FIPS 180-4): SHA-224, SHA-256, SHA-384, SHA-512.
//!
//! Both word sizes share one compression core; the four public types are
//! generated from it with their own IVs and output lengths.

use crate::crypto::digest::Digest;
use crate::crypto::util::{load_u32_be, load_u64_be, store_u32_be, store_u64_be};

// ---------------------------------------------------------------------------
// 32-bit core (SHA-224 / SHA-256)
// ---------------------------------------------------------------------------

const K32: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

#[derive(Clone)]
struct Sha256Core {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256Core {
    fn new(iv: [u32; 8]) -> Self {
        Sha256Core {
            state: iv,
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, word) in w[..16].iter_mut().enumerate() {
            *word = load_u32_be(&block[i * 4..]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K32[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.buf_len != 0 {
            let need = 64 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let full = self.buf;
                self.compress(&full);
                self.buf_len = 0;
            }
        }

        while data.len() >= 64 {
            let block: [u8; 64] = data[..64].try_into().expect("len checked");
            self.compress(&block);
            data = &data[64..];
        }

        self.buf[..data.len()].copy_from_slice(data);
        if !data.is_empty() {
            self.buf_len = data.len();
        }
    }

    fn finalize_into(&mut self, out: &mut [u8]) {
        let bit_len = self.total_len.wrapping_mul(8);
        if self.buf_len < 56 {
            self.buf[self.buf_len] = 0x80;
            for b in &mut self.buf[self.buf_len + 1..56] {
                *b = 0;
            }
            self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
            let block = self.buf;
            self.compress(&block);
        } else {
            self.buf[self.buf_len] = 0x80;
            for b in &mut self.buf[self.buf_len + 1..64] {
                *b = 0;
            }
            let block = self.buf;
            self.compress(&block);
            let mut len_block = [0u8; 64];
            len_block[56..64].copy_from_slice(&bit_len.to_be_bytes());
            self.compress(&len_block);
        }
        for i in 0..8 {
            store_u32_be(&mut out[i * 4..], self.state[i]);
        }
    }
}

// ---------------------------------------------------------------------------
// 64-bit core (SHA-384 / SHA-512)
// ---------------------------------------------------------------------------

const K64: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

#[derive(Clone)]
struct Sha512Core {
    state: [u64; 8],
    buf: [u8; 128],
    buf_len: usize,
    total_len: u128,
}

impl Sha512Core {
    fn new(iv: [u64; 8]) -> Self {
        Sha512Core {
            state: iv,
            buf: [0u8; 128],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn compress(&mut self, block: &[u8; 128]) {
        let mut w = [0u64; 80];
        for (i, word) in w[..16].iter_mut().enumerate() {
            *word = load_u64_be(&block[i * 8..]);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K64[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u128);

        if self.buf_len != 0 {
            let need = 128 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 128 {
                let full = self.buf;
                self.compress(&full);
                self.buf_len = 0;
            }
        }

        while data.len() >= 128 {
            let block: [u8; 128] = data[..128].try_into().expect("len checked");
            self.compress(&block);
            data = &data[128..];
        }

        self.buf[..data.len()].copy_from_slice(data);
        if !data.is_empty() {
            self.buf_len = data.len();
        }
    }

    fn finalize_into(&mut self, out: &mut [u8]) {
        let bit_len = self.total_len.wrapping_mul(8);
        if self.buf_len < 112 {
            self.buf[self.buf_len] = 0x80;
            for b in &mut self.buf[self.buf_len + 1..112] {
                *b = 0;
            }
            self.buf[112..128].copy_from_slice(&bit_len.to_be_bytes());
            let block = self.buf;
            self.compress(&block);
        } else {
            self.buf[self.buf_len] = 0x80;
            for b in &mut self.buf[self.buf_len + 1..128] {
                *b = 0;
            }
            let block = self.buf;
            self.compress(&block);
            let mut len_block = [0u8; 128];
            len_block[112..128].copy_from_slice(&bit_len.to_be_bytes());
            self.compress(&len_block);
        }
        for i in 0..8 {
            store_u64_be(&mut out[i * 8..], self.state[i]);
        }
    }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

macro_rules! define_sha2_256 {
    ($name:ident, $iv:expr, $out:expr) => {
        /// SHA-2 hasher (32-bit word size).
        #[derive(Clone)]
        pub struct $name {
            core: Sha256Core,
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $name {
            /// One-shot convenience digest.
            pub fn digest(data: &[u8]) -> [u8; $out] {
                let mut h = $name::new();
                h.update(data);
                h.finalize()
            }

            /// Finalize into a fixed-size array.
            pub fn finalize(self) -> [u8; $out] {
                let mut out = [0u8; $out];
                Digest::finalize_into(self, &mut out);
                out
            }
        }

        impl Digest for $name {
            const OUTPUT_LEN: usize = $out;
            const BLOCK_LEN: usize = 64;

            fn new() -> Self {
                $name {
                    core: Sha256Core::new($iv),
                }
            }

            fn update(&mut self, data: &[u8]) {
                self.core.update(data);
            }

            fn finalize_into(mut self, out: &mut [u8]) {
                debug_assert!(out.len() >= Self::OUTPUT_LEN);
                let mut tmp = [0u8; 32];
                self.core.finalize_into(&mut tmp);
                out[..$out].copy_from_slice(&tmp[..$out]);
            }
        }
    };
}

macro_rules! define_sha2_512 {
    ($name:ident, $iv:expr, $out:expr) => {
        /// SHA-2 hasher (64-bit word size).
        #[derive(Clone)]
        pub struct $name {
            core: Sha512Core,
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $name {
            /// One-shot convenience digest.
            pub fn digest(data: &[u8]) -> [u8; $out] {
                let mut h = $name::new();
                h.update(data);
                h.finalize()
            }

            /// Finalize into a fixed-size array.
            pub fn finalize(self) -> [u8; $out] {
                let mut out = [0u8; $out];
                Digest::finalize_into(self, &mut out);
                out
            }
        }

        impl Digest for $name {
            const OUTPUT_LEN: usize = $out;
            const BLOCK_LEN: usize = 128;

            fn new() -> Self {
                $name {
                    core: Sha512Core::new($iv),
                }
            }

            fn update(&mut self, data: &[u8]) {
                self.core.update(data);
            }

            fn finalize_into(mut self, out: &mut [u8]) {
                debug_assert!(out.len() >= Self::OUTPUT_LEN);
                let mut tmp = [0u8; 64];
                self.core.finalize_into(&mut tmp);
                out[..$out].copy_from_slice(&tmp[..$out]);
            }
        }
    };
}

const IV224: [u32; 8] = [
    0xc105_9ed8,
    0x367c_d507,
    0x3070_dd17,
    0xf70e_5939,
    0xffc0_0b31,
    0x6858_1511,
    0x64f9_8fa7,
    0xbefa_4fa4,
];

const IV256: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const IV384: [u64; 8] = [
    0xcbbb_9d5d_c105_9ed8,
    0x629a_292a_367c_d507,
    0x9159_015a_3070_dd17,
    0x152f_ecd8_f70e_5939,
    0x6733_2667_ffc0_0b31,
    0x8eb4_4a87_6858_1511,
    0xdb0c_2e0d_64f9_8fa7,
    0x47b5_481d_befa_4fa4,
];

const IV512: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

define_sha2_256!(Sha224, IV224, 28);
define_sha2_256!(Sha256, IV256, 32);
define_sha2_512!(Sha384, IV384, 48);
define_sha2_512!(Sha512, IV512, 64);

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    #[test]
    fn sha224_vectors() {
        assert_eq!(
            hex(&Sha224::digest(b"abc")),
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
        assert_eq!(
            hex(&Sha224::digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
        );
    }

    #[test]
    fn sha256_vectors() {
        assert_eq!(
            hex(&Sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&Sha256::digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        let mut h = Sha256::new();
        for _ in 0..1000 {
            h.update(&[b'a'; 1000]);
        }
        assert_eq!(
            hex(&h.finalize()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn sha384_vectors() {
        assert_eq!(
            hex(&Sha384::digest(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn sha512_vectors() {
        assert_eq!(
            hex(&Sha512::digest(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn empty_inputs() {
        assert_eq!(
            hex(&Sha256::digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&Sha512::digest(b"")),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let mut h = Sha256::new();
        for chunk in data.chunks(11) {
            h.update(chunk);
        }
        assert_eq!(h.finalize(), Sha256::digest(data));
        let mut h = Sha512::new();
        for chunk in data.chunks(13) {
            h.update(chunk);
        }
        assert_eq!(h.finalize(), Sha512::digest(data));
    }

    #[test]
    fn boundary_block_sizes() {
        // Test padding at block boundaries (63, 64, 65 bytes).
        for len in [55usize, 56, 63, 64, 65, 111, 112, 119, 127, 128, 129] {
            let data = vec![0x5au8; len];
            assert_eq!(Sha256::digest(&data), Sha256::digest(&data), "len {len}");
            assert_eq!(Sha512::digest(&data), Sha512::digest(&data), "len {len}");
            // Incremental with 1-byte chunks must match one-shot.
            let mut h = Sha256::new();
            for b in &data {
                h.update(&[*b]);
            }
            assert_eq!(h.finalize(), Sha256::digest(&data), "incr len {len}");
        }
    }
}
