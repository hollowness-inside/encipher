use ibig::UBig;

use super::basic::elgamal_decrypt;
use crate::{keypair::PrivateKey, result::Result};

/// Private key for the ElGamal cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElGamalPrivate {
    pub prime: UBig,
    pub key: UBig,
}

impl PrivateKey for ElGamalPrivate {
    /// Decrypts an ElGamal ciphertext using the private key.
    ///
    /// `message`: A slice containing the two ElGamal ciphertext components (`c1`, `c2`).
    ///
    /// Returns the decrypted message (`UBig`) on success.
    ///
    #[inline]
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        elgamal_decrypt(message, &self.prime, &self.key)
    }

    fn decrypt_marshalled(&self, _message: &[u8]) -> Result<Vec<u8>> {
        unimplemented!()
    }

    #[inline]
    fn encrypt(&self, _message: &[u8]) -> Result<Vec<u8>> {
        unimplemented!()
    }

    #[inline]
    fn encrypt_chunked(&self, _bytes: &[u8], _chunk_size: usize) -> Result<Vec<u8>> {
        unimplemented!()
    }
}
