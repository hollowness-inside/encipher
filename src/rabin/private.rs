use ibig::UBig;

use super::basic::rabin_decrypt;
use crate::{keypair::PrivateKey, result::Result};

/// Private key for the Rabin cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RabinPrivate {
    /// First prime factor of the public modulus.
    pub prime_1: UBig,

    /// Second prime factor of the public modulus.
    pub prime_2: UBig,
}

impl PrivateKey for RabinPrivate {
    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>> {
        unimplemented!()
    }

    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        rabin_decrypt(message, &self.prime_1, &self.prime_2)
    }
}
