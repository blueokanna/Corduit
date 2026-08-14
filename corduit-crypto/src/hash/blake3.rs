//! BLAKE3 (tree hash, XOF).
//!
//! This is a faithful, dependency-free port of the reference implementation
//! (BLAKE3 team). It follows the specification exactly: 7-round compression
//! with the BLAKE3 message permutation, 1024-byte chunks, and the CV-stack
//! tree algorithm. Single-threaded; portable and constant-time where it
//! matters (no data-dependent branches in the compression).

use crate::util::load_u32_le;

const OUT_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;
/// Max CV stack entries: 2^54 chunks × 1024 = 2^64 bytes.
const MAX_STACK: usize = 54;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const KEYED_HASH: u32 = 1 << 4;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

const IV: [u32; 8] = [
    0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab,
    0x5be0_cd19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[inline]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

fn permute(m: &mut [u32; 16]) {
    let mut permuted = [0u32; 16];
    for i in 0..16 {
        permuted[i] = m[MSG_PERMUTATION[i]];
    }
    *m = permuted;
}

/// The BLAKE3 compression function. Returns the full 16-word state.
fn compress(
    chaining_value: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [
        chaining_value[0], chaining_value[1], chaining_value[2], chaining_value[3],
        chaining_value[4], chaining_value[5], chaining_value[6], chaining_value[7],
        IV[0], IV[1], IV[2], IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut block = *block_words;

    round(&mut state, &block);
    permute(&mut block);
    round(&mut state, &block);
    permute(&mut block);
    round(&mut state, &block);
    permute(&mut block);
    round(&mut state, &block);
    permute(&mut block);
    round(&mut state, &block);
    permute(&mut block);
    round(&mut state, &block);
    permute(&mut block);
    round(&mut state, &block);

    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= chaining_value[i];
    }
    state
}

fn first_8_words(compression_output: [u32; 16]) -> [u32; 8] {
    compression_output[..8].try_into().expect("8 words")
}

fn words_from_le_bytes(bytes: &[u8]) -> [u32; 16] {
    let mut words = [0u32; 16];
    for (i, word) in words.iter_mut().enumerate() {
        *word = load_u32_le(&bytes[i * 4..]);
    }
    words
}

/// State captured just before choosing between a chaining value and root
/// output bytes.
struct Output {
    input_cv: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        first_8_words(compress(
            &self.input_cv,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        ))
    }

    fn root_output_bytes(&self, out_slice: &mut [u8]) {
        let mut output_block_counter = 0u64;
        for out_block in out_slice.chunks_mut(2 * OUT_LEN) {
            let words = compress(
                &self.input_cv,
                &self.block_words,
                output_block_counter,
                self.block_len,
                self.flags | ROOT,
            );
            for (word, out_word) in words.iter().zip(out_block.chunks_mut(4)) {
                out_word.copy_from_slice(&word.to_le_bytes()[..out_word.len()]);
            }
            output_block_counter = output_block_counter.wrapping_add(1);
        }
    }
}

#[derive(Clone)]
struct ChunkState {
    chaining_value: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: u8,
    blocks_compressed: u8,
    flags: u32,
}

impl ChunkState {
    fn new(key_words: [u32; 8], chunk_counter: u64, flags: u32) -> Self {
        ChunkState {
            chaining_value: key_words,
            chunk_counter,
            block: [0u8; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed as usize + self.block_len as usize
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.block_len as usize == BLOCK_LEN {
                let block_words = words_from_le_bytes(&self.block);
                self.chaining_value = first_8_words(compress(
                    &self.chaining_value,
                    &block_words,
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    self.flags | self.start_flag(),
                ));
                self.blocks_compressed += 1;
                self.block = [0u8; BLOCK_LEN];
                self.block_len = 0;
            }

            let want = BLOCK_LEN - self.block_len as usize;
            let take = want.min(input.len());
            self.block[self.block_len as usize..][..take].copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        let block_words = words_from_le_bytes(&self.block);
        Output {
            input_cv: self.chaining_value,
            block_words,
            counter: self.chunk_counter,
            block_len: self.block_len as u32,
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

fn parent_output(left_child_cv: [u32; 8], right_child_cv: [u32; 8], key_words: [u32; 8], flags: u32) -> Output {
    let mut block_words = [0u32; 16];
    block_words[..8].copy_from_slice(&left_child_cv);
    block_words[8..].copy_from_slice(&right_child_cv);
    Output {
        input_cv: key_words,
        block_words,
        counter: 0,                 // parents always use counter 0
        block_len: BLOCK_LEN as u32,
        flags: PARENT | flags,
    }
}

fn parent_cv(left: [u32; 8], right: [u32; 8], key: [u32; 8], flags: u32) -> [u32; 8] {
    parent_output(left, right, key, flags).chaining_value()
}

/// Incremental BLAKE3 hasher.
#[derive(Clone)]
pub struct Blake3 {
    chunk_state: ChunkState,
    key_words: [u32; 8],
    cv_stack: [[u32; 8]; MAX_STACK],
    cv_stack_len: usize,
    flags: u32,
}

impl Blake3 {
    fn new_internal(key_words: [u32; 8], flags: u32) -> Self {
        Blake3 {
            chunk_state: ChunkState::new(key_words, 0, flags),
            key_words,
            cv_stack: [[0u8 as u32; 8]; MAX_STACK],
            cv_stack_len: 0,
            flags,
        }
    }

    /// Standard BLAKE3 hash.
    pub fn new() -> Self {
        Self::new_internal(IV, 0)
    }

    /// Keyed BLAKE3 (32-byte key).
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        let mut key_words = [0u32; 8];
        for (i, word) in key_words.iter_mut().enumerate() {
            *word = load_u32_le(&key[i * 4..]);
        }
        Self::new_internal(key_words, KEYED_HASH)
    }

    /// BLAKE3 key-derivation mode. The context string should be hardcoded,
    /// globally unique and application-specific.
    pub fn new_derive_key(context: &[u8]) -> Self {
        let mut context_hasher = Self::new_internal(IV, DERIVE_KEY_CONTEXT);
        context_hasher.update(context);
        let mut context_key = [0u8; 32];
        context_hasher.finalize_xof_into(&mut context_key);
        let mut key_words = [0u32; 8];
        for (i, word) in key_words.iter_mut().enumerate() {
            *word = load_u32_le(&context_key[i * 4..]);
        }
        Self::new_internal(key_words, DERIVE_KEY_MATERIAL)
    }

    fn push_stack(&mut self, cv: [u32; 8]) {
        self.cv_stack[self.cv_stack_len] = cv;
        self.cv_stack_len += 1;
    }

    fn pop_stack(&mut self) -> [u32; 8] {
        self.cv_stack_len -= 1;
        self.cv_stack[self.cv_stack_len]
    }

    /// Section 5.1.2 of the BLAKE3 spec: add a chunk chaining value and
    /// merge any completed subtrees.
    fn add_chunk_chaining_value(&mut self, mut new_cv: [u32; 8], mut total_chunks: u64) {
        while total_chunks & 1 == 0 {
            new_cv = parent_cv(self.pop_stack(), new_cv, self.key_words, self.flags);
            total_chunks >>= 1;
        }
        self.push_stack(new_cv);
    }

    /// Absorb input.
    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk_state.len() == CHUNK_LEN {
                let chunk_cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_chaining_value(chunk_cv, total_chunks);
                self.chunk_state = ChunkState::new(self.key_words, total_chunks, self.flags);
            }

            let want = CHUNK_LEN - self.chunk_state.len();
            let take = want.min(input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
    }

    /// Finalize the hash, writing any number of output bytes (XOF).
    pub fn finalize_xof_into(&self, out_slice: &mut [u8]) {
        let mut output = self.chunk_state.output();
        let mut parent_nodes_remaining = self.cv_stack_len;
        while parent_nodes_remaining > 0 {
            parent_nodes_remaining -= 1;
            output = parent_output(
                self.cv_stack[parent_nodes_remaining],
                output.chaining_value(),
                self.key_words,
                self.flags,
            );
        }
        output.root_output_bytes(out_slice);
    }

    /// Finalize into a 32-byte digest (non-consuming, like the reference).
    pub fn finalize(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.finalize_xof_into(&mut out);
        out
    }
}

impl Default for Blake3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake3 {
    /// One-shot convenience: BLAKE3-256 of `data`.
    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut h = Blake3::new();
        h.update(data);
        h.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the official test-vector input: the repeating sequence
    /// 0,1,2,...,249,250,0,1,... of the given length.
    fn vec_input(len: usize) -> Vec<u8> {
        (0u8..=250).cycle().take(len).collect()
    }

    fn hex32(b: &[u8; 32]) -> String {
        let mut s = String::new();
        for x in b {
            s.push_str(&format!("{:02x}", x));
        }
        s
    }

    #[test]
    fn official_vectors() {
        // Official BLAKE3 test vectors (test_vectors.json).
        assert_eq!(
            hex32(&Blake3::digest(b"")),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(
            hex32(&Blake3::digest(&vec_input(1))),
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"
        );
        assert_eq!(
            hex32(&Blake3::digest(&vec_input(63))),
            "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"
        );
        assert_eq!(
            hex32(&Blake3::digest(&vec_input(64))),
            "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"
        );
        assert_eq!(
            hex32(&Blake3::digest(&vec_input(127))),
            "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d"
        );
        // Exactly one chunk.
        assert_eq!(
            hex32(&Blake3::digest(&vec_input(1024))),
            "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"
        );
        // Crosses into the second chunk.
        assert_eq!(
            hex32(&Blake3::digest(&vec_input(1025))),
            "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"
        );
        // Two full chunks: exercises the parent node.
        assert_eq!(
            hex32(&Blake3::digest(&vec_input(2048))),
            "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"
        );
        // 8 KiB: deeper tree.
        assert_eq!(
            hex32(&Blake3::digest(&vec_input(8192))),
            "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63"
        );
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data: Vec<u8> = (0u8..=255).cycle().take(5000).collect();
        let mut h = Blake3::new();
        for chunk in data.chunks(137) {
            h.update(chunk);
        }
        assert_eq!(h.finalize(), Blake3::digest(&data));
    }

    #[test]
    fn xof_prefix_matches_32() {
        let data = b"xof test";
        let mut h = Blake3::new();
        h.update(data);
        let mut big = [0u8; 64];
        h.finalize_xof_into(&mut big);
        assert_eq!(&big[..32], &h.finalize()[..]);
    }
}
