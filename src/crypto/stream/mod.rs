//! Stream ciphers and block-cipher modes.
//!
//! Everything here exists for a wire format that names it: ChaCha20 (RFC 8439)
//! for the current generation, and the Salsa20 / RC4 / CFB / CTR shapes that
//! ShadowsocksR and the older Shadowsocks methods still require. The two
//! weak ciphers (RC4, and CFB/CTR which are unauthenticated by construction)
//! are documented as such at their definitions rather than being quietly
//! available — the outbounds that use them authenticate separately.

mod aes;
mod chacha20;
mod modes;
mod rc4;
mod salsa20;

pub use aes::Aes;
pub use chacha20::{ChaCha20, ChaCha20Legacy};
pub use modes::{Cbc, Cfb128, Ctr};
pub use rc4::Rc4;
pub use salsa20::Salsa20;
