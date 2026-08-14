//! Base64 and hex encodings.

mod base64;
mod hex;

pub use base64::{decode, decode_into, encode, encode_into, encoded_len, Alphabet, Config, DecodeError};
pub use hex::{decode as hex_decode, encode as hex_encode, DecodeError as HexDecodeError};
