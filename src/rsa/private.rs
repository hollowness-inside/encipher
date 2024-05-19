use ibig::UBig;

use super::basic::{rsa_decrypt, rsa_encrypt};
use crate::{keypair::CryptoKey, result::Result};

/// Private key for the RSA algorithm.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RsaPrivate {
    /// Private exponent used for decryption.
    pub exponent: UBig,

    /// First prime factor of the public modulus.
    pub prime_1: UBig,

    /// Second prime factor of the public modulus.
    pub prime_2: UBig,
}

impl CryptoKey for RsaPrivate {
    #[inline]
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        let div = &self.prime_1 * &self.prime_2;
        rsa_decrypt(message, &self.exponent, &div)
    }

    #[inline]
    fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        let div = &self.prime_1 * &self.prime_2;
        rsa_encrypt(message, &self.exponent, &div)
    }
}
