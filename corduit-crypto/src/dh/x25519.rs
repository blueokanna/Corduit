//! X25519 (RFC 7748) — Curve25519 Diffie-Hellman.
//!
//! Field arithmetic uses 5×51-bit limbs in GF(2^255-19) with a constant-time
//! Montgomery ladder. No secret-dependent branches, no secret table lookups.

const MASK51: u64 = (1 << 51) - 1;
/// a24 = (486662 - 2) / 4 for the Montgomery ladder.
const A24: u64 = 121665;

/// A field element in GF(2^255-19), stored as 5 limbs of 51 bits each
/// (little-endian by limb weight). Limbs may be "lazy" (up to 2^52) between
/// operations; [`fe_reduce`] normalizes them.
#[derive(Clone, Copy)]
struct Fe([u64; 5]);

impl Fe {
    fn zero() -> Fe {
        Fe([0; 5])
    }

    fn one() -> Fe {
        let mut f = Fe::zero();
        f.0[0] = 1;
        f
    }

    fn from_bytes(b: &[u8; 32]) -> Fe {
        // Decode the little-endian 255-bit value into five 51-bit limbs.
        let b0 = b[0] as u64;
        let b1 = b[1] as u64;
        let b2 = b[2] as u64;
        let b3 = b[3] as u64;
        let b4 = b[4] as u64;
        let b5 = b[5] as u64;
        let b6 = b[6] as u64;
        let b7 = b[7] as u64;
        let b8 = b[8] as u64;
        let b9 = b[9] as u64;
        let b10 = b[10] as u64;
        let b11 = b[11] as u64;
        let b12 = b[12] as u64;
        let b13 = b[13] as u64;
        let b14 = b[14] as u64;
        let b15 = b[15] as u64;
        let b16 = b[16] as u64;
        let b17 = b[17] as u64;
        let b18 = b[18] as u64;
        let b19 = b[19] as u64;
        let b20 = b[20] as u64;
        let b21 = b[21] as u64;
        let b22 = b[22] as u64;
        let b23 = b[23] as u64;
        let b24 = b[24] as u64;
        let b25 = b[25] as u64;
        let b26 = b[26] as u64;
        let b27 = b[27] as u64;
        let b28 = b[28] as u64;
        let b29 = b[29] as u64;
        let b30 = b[30] as u64;

        // limb 0 = bits  0-50
        // limb 1 = bits 51-101
        // limb 2 = bits 102-152
        // limb 3 = bits 153-203
        // limb 4 = bits 204-254
        Fe([
            b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) | (b4 << 32) | (b5 << 40)
                | ((b6 & 0x07) << 48),
            (b6 >> 3) | (b7 << 5) | (b8 << 13) | (b9 << 21) | (b10 << 29) | (b11 << 37)
                | ((b12 & 0x3f) << 45),
            (b12 >> 6) | (b13 << 2) | (b14 << 10) | (b15 << 18) | (b16 << 26) | (b17 << 34)
                | (b18 << 42) | ((b19 & 0x01) << 50),
            (b19 >> 1) | (b20 << 7) | (b21 << 15) | (b22 << 23) | (b23 << 31) | (b24 << 39)
                | ((b25 & 0x0f) << 47),
            (b25 >> 4) | (b26 << 4) | (b27 << 12) | (b28 << 20) | (b29 << 28) | (b30 << 36)
                | ((b[31] as u64 & 0x7f) << 44),
        ])
    }

    fn to_bytes(self) -> [u8; 32] {
        let f = fe_reduce(self);
        let l0 = f.0[0];
        let l1 = f.0[1];
        let l2 = f.0[2];
        let l3 = f.0[3];
        let l4 = f.0[4];

        let mut out = [0u8; 32];
        out[0] = l0 as u8;
        out[1] = (l0 >> 8) as u8;
        out[2] = (l0 >> 16) as u8;
        out[3] = (l0 >> 24) as u8;
        out[4] = (l0 >> 32) as u8;
        out[5] = (l0 >> 40) as u8;
        out[6] = ((l0 >> 48) | (l1 << 3)) as u8;
        out[7] = (l1 >> 5) as u8;
        out[8] = (l1 >> 13) as u8;
        out[9] = (l1 >> 21) as u8;
        out[10] = (l1 >> 29) as u8;
        out[11] = (l1 >> 37) as u8;
        out[12] = ((l1 >> 45) | (l2 << 6)) as u8;
        out[13] = (l2 >> 2) as u8;
        out[14] = (l2 >> 10) as u8;
        out[15] = (l2 >> 18) as u8;
        out[16] = (l2 >> 26) as u8;
        out[17] = (l2 >> 34) as u8;
        out[18] = (l2 >> 42) as u8;
        out[19] = ((l2 >> 50) | (l3 << 1)) as u8;
        out[20] = (l3 >> 7) as u8;
        out[21] = (l3 >> 15) as u8;
        out[22] = (l3 >> 23) as u8;
        out[23] = (l3 >> 31) as u8;
        out[24] = (l3 >> 39) as u8;
        out[25] = ((l3 >> 47) | (l4 << 4)) as u8;
        out[26] = (l4 >> 4) as u8;
        out[27] = (l4 >> 12) as u8;
        out[28] = (l4 >> 20) as u8;
        out[29] = (l4 >> 28) as u8;
        out[30] = (l4 >> 36) as u8;
        out[31] = ((l4 >> 44) & 0x7f) as u8;
        out
    }
}

/// Full carry + conditional subtraction of p, producing a canonical
/// representative (every limb < 2^51, value < p).
fn fe_reduce(mut f: Fe) -> Fe {
    let mut t = f.0;
    let mut c;

    c = t[0] >> 51;
    t[0] &= MASK51;
    t[1] += c;
    c = t[1] >> 51;
    t[1] &= MASK51;
    t[2] += c;
    c = t[2] >> 51;
    t[2] &= MASK51;
    t[3] += c;
    c = t[3] >> 51;
    t[3] &= MASK51;
    t[4] += c;
    c = t[4] >> 51;
    t[4] &= MASK51;
    t[0] += c * 19;
    c = t[0] >> 51;
    t[0] &= MASK51;
    t[1] += c;
    c = t[1] >> 51;
    t[1] &= MASK51;
    t[2] += c;
    c = t[2] >> 51;
    t[2] &= MASK51;
    t[3] += c;
    c = t[3] >> 51;
    t[3] &= MASK51;
    t[4] += c;

    // Now t < 2^255 (all limbs < 2^51). Conditionally subtract p.
    // p = [2^51-19, 2^51-1, 2^51-1, 2^51-1, 2^51-1]
    let p = [MASK51 - 18, MASK51, MASK51, MASK51, MASK51];
    let mut d = [0u64; 5];
    let mut borrow = 0u64;
    for i in 0..5 {
        let (di, b) = t[i].overflowing_sub(p[i].wrapping_add(borrow));
        d[i] = di;
        borrow = b as u64;
    }
    // borrow == 1 → t < p → keep t; borrow == 0 → t >= p → use t - p.
    let mask = borrow.wrapping_neg(); // all-ones if keep t, 0 if use d
    for i in 0..5 {
        t[i] = (t[i] & mask) | (d[i] & !mask);
    }

    f.0 = t;
    f
}

fn fe_add(a: Fe, b: Fe) -> Fe {
    Fe([
        a.0[0] + b.0[0],
        a.0[1] + b.0[1],
        a.0[2] + b.0[2],
        a.0[3] + b.0[3],
        a.0[4] + b.0[4],
    ])
}

fn fe_sub(a: Fe, b: Fe) -> Fe {
    // Canonicalize both inputs first so the borrow subtraction below is a
    // clean base-2^51 operation with no wrapped limbs near 2^64.
    let a = fe_reduce(a);
    let b = fe_reduce(b);

    // d = a - b with borrow, in base 2^51.  When a[i] < b[i] + borrow the
    // u64 subtraction wraps; add back 2^51 and propagate the borrow.
    let mut d = [0u64; 5];
    let mut borrow = 0u64;
    for i in 0..5 {
        let (mut di, b2) = a.0[i].overflowing_sub(b.0[i].wrapping_add(borrow));
        borrow = b2 as u64;
        if borrow == 1 {
            di = di.wrapping_add(1u64 << 51);
        }
        d[i] = di;
    }

    // If a < b then d = a - b + 2^255, and since p = 2^255 - 19, the
    // reduced value is a - b + p = d - 19.
    let mut dm = [0u64; 5];
    let mut borrow2 = 0u64;
    for i in 0..5 {
        let sub: u64 = if i == 0 { 19 } else { 0 };
        let (mut v, b3) = d[i].overflowing_sub(sub.wrapping_add(borrow2));
        borrow2 = b3 as u64;
        if borrow2 == 1 {
            v = v.wrapping_add(1u64 << 51);
        }
        dm[i] = v;
    }

    // Constant-time select: borrow == 1 → d - 19, else d.
    let mask = borrow.wrapping_neg();
    let mut out = [0u64; 5];
    for i in 0..5 {
        out[i] = (d[i] & !mask) | (dm[i] & mask);
    }
    Fe(out)
}

fn fe_mul(a: Fe, b: Fe) -> Fe {
    let a0 = a.0[0] as u128;
    let a1 = a.0[1] as u128;
    let a2 = a.0[2] as u128;
    let a3 = a.0[3] as u128;
    let a4 = a.0[4] as u128;
    let b0 = b.0[0] as u128;
    let b1 = b.0[1] as u128;
    let b2 = b.0[2] as u128;
    let b3 = b.0[3] as u128;
    let b4 = b.0[4] as u128;

    // Fold the high-limb products mod 2^255-19 (2^255 ≡ 19) during the
    // accumulation. Each c_i stays below 2^110, safe in u128.
    let c0 = a0 * b0 + a1 * b4 * 19 + a2 * b3 * 19 + a3 * b2 * 19 + a4 * b1 * 19;
    let c1 = a0 * b1 + a1 * b0 + a2 * b4 * 19 + a3 * b3 * 19 + a4 * b2 * 19;
    let c2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4 * 19 + a4 * b3 * 19;
    let c3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4 * 19;
    let c4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

    // Carry chain in u128.
    let mut c;
    let mut r0 = c0 & MASK51 as u128;
    c = c0 >> 51;
    let mut t = c1 + c;
    let mut r1 = t & MASK51 as u128;
    c = t >> 51;
    t = c2 + c;
    let r2 = t & MASK51 as u128;
    c = t >> 51;
    t = c3 + c;
    let r3 = t & MASK51 as u128;
    c = t >> 51;
    t = c4 + c;
    let r4 = t & MASK51 as u128;
    c = t >> 51;
    // The carry out of limb 4 is 2^255 ≡ 19.
    t = r0 + c * 19;
    r0 = t & MASK51 as u128;
    c = t >> 51;
    r1 += c;

    Fe([r0 as u64, r1 as u64, r2 as u64, r3 as u64, r4 as u64])
}

fn fe_square(a: Fe) -> Fe {
    fe_mul(a, a)
}

/// `x^(p-2)` = `x^(-1)` via square-and-multiply over the public exponent
/// `p - 2 = 2^255 - 21`. The exponent is public, so branching on its bits is
/// safe; the base is secret.
///
/// The bits are consumed most-significant first, squaring the running
/// result on every step and multiplying by `x` only for set bits. (The
/// multiply-then-square variant with an LSB-first scan computes the
/// bit-reversed exponent and is subtly wrong.)
fn fe_invert(x: Fe) -> Fe {
    // p - 2 = 2^255 - 21, little-endian bytes: 0xeb, then 30 bytes of 0xff,
    // then 0x7f (2^255 - 21 = 0x7f ff ff ... ff eb).
    let e: [u8; 32] = [
        0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    let mut result = Fe::one();
    // Iterate over the 255 bits of p-2 (little-endian), MSB first.
    for t in (0..255).rev() {
        result = fe_square(result);
        if ((e[t / 8] >> (t % 8)) & 1) == 1 {
            result = fe_mul(result, x);
        }
    }
    fe_reduce(result)
}

/// Constant-time conditional swap.
fn cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
    let mask = swap.wrapping_neg();
    for i in 0..5 {
        let t = mask & (a.0[i] ^ b.0[i]);
        a.0[i] ^= t;
        b.0[i] ^= t;
    }
}

/// Clamp a 32-byte scalar per RFC 7748.
fn clamp(scalar: &mut [u8; 32]) {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
}

/// X25519: returns `scalar * basepoint`'s u-coordinate.
///
/// `scalar` is clamped internally. Passing all-zero `u` yields all-zero
/// output (the low-order-point corner case), matching RFC 7748.
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    clamp(&mut k);

    let x1 = Fe::from_bytes(u);
    let mut x2 = Fe::one();
    let mut z2 = Fe::zero();
    let mut x3 = x1;
    let mut z3 = Fe::one();
    let mut swap = 0u64;

    for t in (0..255).rev() {
        let k_t = ((k[t / 8] >> (t % 8)) & 1) as u64;
        swap ^= k_t;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = k_t;

        let a = fe_add(x2, z2);
        let aa = fe_square(a);
        let b = fe_sub(x2, z2);
        let bb = fe_square(b);
        let e = fe_sub(aa, bb);
        let c = fe_add(x3, z3);
        let d = fe_sub(x3, z3);
        let da = fe_mul(d, a);
        let cb = fe_mul(c, b);
        let t1 = fe_add(da, cb);
        x3 = fe_square(t1);
        let t2 = fe_sub(da, cb);
        let t3 = fe_square(t2);
        z3 = fe_mul(x1, t3);
        x2 = fe_mul(aa, bb);
        let a24e = fe_mul(Fe([A24, 0, 0, 0, 0]), e);
        let a24e_plus_aa = fe_add(aa, a24e);
        z2 = fe_mul(e, a24e_plus_aa);
    }

    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);

    let zinv = fe_invert(z2);
    let result = fe_mul(x2, zinv);
    result.to_bytes()
}

/// Compute the X25519 public key from a private key.
pub fn public_key(private: &[u8; 32]) -> [u8; 32] {
    let basepoint = [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ];
    x25519(private, &basepoint)
}

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
    fn rfc7748_test_vector_1() {
        // RFC 7748 §5.2, first vector.
        let scalar = [
            0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46,
            0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44,
            0xba, 0x44, 0x9a, 0xc4,
        ];
        let u = [
            0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1,
            0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6,
            0xd0, 0xab, 0x1c, 0x4c,
        ];
        let expected = [
            0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d,
            0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55,
            0x77, 0xa2, 0x85, 0x52,
        ];
        let got = x25519(&scalar, &u);
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc7748_test_vector_2() {
        // RFC 7748 §5.2 second vector.
        let scalar = [
            0x4b, 0x66, 0xe9, 0xd4, 0xd1, 0xb4, 0x67, 0x3c, 0x5a, 0xd2, 0x26, 0x91, 0x95, 0x7d,
            0x6a, 0xf5, 0xc1, 0x1b, 0x64, 0x21, 0xe0, 0xea, 0x01, 0xd4, 0x2c, 0xa4, 0x16, 0x9e,
            0x79, 0x18, 0xba, 0x0d,
        ];
        let u = [
            0xe5, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3, 0xf4, 0xb7, 0x95, 0x9d, 0x05, 0x38,
            0xae, 0x2c, 0x31, 0xdb, 0xe7, 0x10, 0x6f, 0xc0, 0x3c, 0x3e, 0xfc, 0x4c, 0xd5, 0x49,
            0xc7, 0x15, 0xa4, 0x93,
        ];
        let expected = [
            0x95, 0xcb, 0xde, 0x94, 0x76, 0xe8, 0x90, 0x7d, 0x7a, 0xad, 0xe4, 0x5c, 0xb4, 0xb8,
            0x73, 0xf8, 0x8b, 0x59, 0x5a, 0x68, 0x79, 0x9f, 0xa1, 0x52, 0xe6, 0xf8, 0xf7, 0x64,
            0x7a, 0xac, 0x79, 0x57,
        ];
        assert_eq!(x25519(&scalar, &u), expected);
    }

    #[test]
    fn rfc7748_iterated() {
        // RFC 7748 §5.2: u_i = X25519(k=u_{i-1}, u_{i-1}), k_0 = u_0 = 9.
        // Values for iterations 1..3 cross-checked against x25519-dalek; the
        // famous 684cf59b... digest is the state after 1000 iterations, not
        // the 2nd.
        let mut k = [0u8; 32];
        k[0] = 9;
        let mut u = k;
        let out = x25519(&k, &u);
        assert_eq!(
            hex(&out),
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
        );
        k = out;
        u = out;
        let out2 = x25519(&k, &u);
        assert_eq!(
            hex(&out2),
            "0e9999075b796ad663980589e9ffddf9a86f5fafc0e143d6ab7a41c11518c302"
        );
        k = out2;
        u = out2;
        let out3 = x25519(&k, &u);
        assert_eq!(
            hex(&out3),
            "2db938cc602d22ff8252aa61e4c9b4398341a97aad6cd658824a85a0b140400c"
        );
    }

    #[test]
    fn rfc7748_ecdh_vector() {
        // RFC 7748 §6.1: Alice's public key.
        let a = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        assert_eq!(
            hex(&public_key(&a)),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
    }

    #[test]
    fn zero_u_gives_zero() {
        let scalar = [1u8; 32];
        let u = [0u8; 32];
        assert_eq!(x25519(&scalar, &u), [0u8; 32]);
    }
}
