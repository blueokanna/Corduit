//! Small internal helpers.

/// A random DNS transaction ID (`u16`), sourced from OS entropy.
#[inline]
pub(crate) fn random_id() -> u16 {
    let mut b = [0u8; 2];
    getrandom::fill(&mut b).expect("OS RNG unavailable");
    u16::from_le_bytes(b)
}
