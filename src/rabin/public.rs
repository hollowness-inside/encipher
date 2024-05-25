use ibig::UBig;

use super::basic::rabin_encrypt;
use crate::{keypair::PublicKey, result::Result};

/// Public key for the Rabin cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RabinPublic {
    /// Public modulus used for encryption.
    pub divisor: UBig,
}

impl PublicKey for RabinPublic {
    fn verify(&self, _message: &[u8]) -> Result<bool> {
        todo!()
    }

    fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        rabin_encrypt(message, &self.divisor)
    }
}
