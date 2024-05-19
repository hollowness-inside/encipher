use ibig::UBig;

use super::basic::{rsa_decrypt, rsa_encrypt};
use crate::{keypair::CryptoKey, result::Result};

/// Public key for the RSA algorithm.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RsaPublic {
    /// Public exponent used for encryption.
    pub exponent: UBig,

    /// Public modulus used for encryption.
    pub divisor: UBig,
}

impl CryptoKey for RsaPublic {
    #[inline]
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        rsa_encrypt(bytes, &self.exponent, &self.divisor)
    }

    #[inline]
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        rsa_decrypt(message, &self.exponent, &self.divisor)
    }
}
