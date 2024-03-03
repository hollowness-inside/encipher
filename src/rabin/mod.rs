mod pair;
mod private;
mod public;

pub(crate) const MAGIC: &[u8; 8] = b"\x00RABIN\x00\x01";

pub use pair::RabinKeyPair;
pub use private::RabinPrivate;
pub use public::RabinPublic;
