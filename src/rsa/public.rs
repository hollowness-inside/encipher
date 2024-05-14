use ibig::UBig;

use super::basic::{rsa_decrypt, rsa_decrypt_marshalled, rsa_encrypt, rsa_encrypt_chunked};
use crate::{keypair::PublicKey, result::Result};

/// Public key for the RSA algorithm.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RsaPublic {
    /// Public exponent used for encryption.
    pub exponent: UBig,

    /// Public modulus used for encryption.
    pub divisor: UBig,
}

impl PublicKey for RsaPublic {
    /// Encrypts a byte slice using the RSA public key.
    ///
    /// This method takes a slice of bytes (`bytes`) as input and returns a `Result` containing either:
    /// * The encrypted message on success.
    /// * An `Error` indicating the reason for failure, specifically `Error::SmallKey` if the message is too large for the key.
    ///
    #[inline]
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        rsa_encrypt(bytes, &self.exponent, &self.divisor)
    }

    #[inline]
    fn encrypt_chunked(&self, bytes: &[u8], chunk_size: usize) -> Result<Vec<u8>> {
        rsa_encrypt_chunked(bytes, &self.exponent, &self.divisor, chunk_size)
    }

    #[inline]
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        rsa_decrypt(message, &self.exponent, &self.divisor)
    }

    #[inline]
    fn decrypt_marshalled(&self, message: &[u8]) -> Result<Vec<u8>> {
        rsa_decrypt_marshalled(message, &self.exponent, &self.divisor)
    }
}
