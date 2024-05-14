use ibig::UBig;

use super::basic::{rsa_decrypt, rsa_decrypt_marshalled, rsa_encrypt, rsa_encrypt_chunked};
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
    /// Decrypts a message received using the corresponding RSA public key.
    ///
    /// This method takes a message as a `UBig` and returns the decrypted message as a `UBig`.
    ///
    #[inline]
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        let div = &self.prime_1 * &self.prime_2;
        rsa_decrypt(message, &self.exponent, &div)
    }

    #[inline]
    fn decrypt_marshalled(&self, message: &[u8]) -> Result<Vec<u8>> {
        let div = &self.prime_1 * &self.prime_2;
        rsa_decrypt_marshalled(message, &self.exponent, &div)
    }

    #[inline]
    fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        let div = &self.prime_1 * &self.prime_2;
        rsa_encrypt(message, &self.exponent, &div)
    }

    #[inline]
    fn encrypt_chunked(&self, bytes: &[u8], chunk_size: usize) -> Result<Vec<u8>> {
        let div = &self.prime_1 * &self.prime_2;
        rsa_encrypt_chunked(bytes, &self.exponent, &div, chunk_size)
    }
}
