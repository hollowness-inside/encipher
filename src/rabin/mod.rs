mod pair;
mod private;
mod public;

/// This constant value (`MAGIC`) is used to pad encrypted messages
/// with the Rabin cryptosystem. This padding helps identify the
/// original message among the four possible decryption candidates
/// returned due to Rabin's inherent ambiguity.
pub(crate) const MAGIC: &[u8; 8] = b"\x00RABIN\x00\x01";

pub use pair::RabinKeyPair;
pub use private::RabinPrivate;
pub use public::RabinPublic;
