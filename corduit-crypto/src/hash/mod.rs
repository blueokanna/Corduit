//! Cryptographic hash functions.
//!
//! | type          | spec        | output |
//! |---------------|-------------|--------|
//! | [`Md5`]       | RFC 1321    | 16     |
//! | [`Sha1`]      | FIPS 180-4  | 20     |
//! | [`Sha224`]    | FIPS 180-4  | 28     |
//! | [`Sha256`]    | FIPS 180-4  | 32     |
//! | [`Sha384`]    | FIPS 180-4  | 48     |
//! | [`Sha512`]    | FIPS 180-4  | 64     |
//! | [`Sha3_224`]  | FIPS 202    | 28     |
//! | [`Sha3_256`]  | FIPS 202    | 32     |
//! | [`Sha3_384`]  | FIPS 202    | 48     |
//! | [`Sha3_512`]  | FIPS 202    | 64     |
//! | [`Blake2b`]   | RFC 7693    | ≤ 64   |
//! | [`Blake2s`]   | RFC 7693    | ≤ 32   |
//! | [`Blake3`]    | BLAKE3 spec | 32/XOF |

mod blake2;
mod blake3;
mod md5;
mod sha1;
mod sha2;
mod sha3;

pub use blake2::{Blake2b, Blake2s};
pub use blake3::Blake3;
pub use md5::Md5;
pub use sha1::Sha1;
pub use sha2::{Sha224, Sha256, Sha384, Sha512};
pub use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
