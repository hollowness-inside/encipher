use ibig::UBig;

use super::basic::{rsa_decrypt, rsa_encrypt};
use crate::{keypair::PrivateKey, result::Result};

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

impl PrivateKey for RsaPrivate {
    fn sign<H: Fn(&[u8]) -> Vec<u8>>(&self, message: &[u8], hashf: &H) -> Result<Vec<u8>> {
        let message = hashf(message);

        let div = &self.prime_1 * &self.prime_2;
        rsa_encrypt(&message, &self.exponent, &div)
    }

    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        let div = &self.prime_1 * &self.prime_2;
        rsa_decrypt(message, &self.exponent, &div)
    }
}
