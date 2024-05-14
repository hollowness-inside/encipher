use ibig::UBig;

use super::basic::{rsa_decrypt, rsa_encrypt};
use crate::utils::{marshal_bytes, pad_message};
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

    fn encrypt_chunked(&self, bytes: &[u8], chunk_size: usize) -> Result<Vec<u8>> {
        let content: Vec<Vec<_>> = pad_message(&bytes, chunk_size)
            .chunks(chunk_size - 1)
            .map(|chunk| self.encrypt(chunk))
            .collect::<Result<_>>()?;

        Ok(marshal_bytes(&content))
    }

    #[inline]
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        rsa_decrypt(message, &self.exponent, &self.divisor)
    }
}
