use ibig::UBig;

use super::basic::{elgamal_encrypt, elgamal_encrypt_chunked};
use crate::{keypair::PublicKey, result::Result};

/// Public key for the ElGamal cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElGamalPublic {
    pub prime: UBig,
    pub alpha: UBig,
    pub beta: UBig,
}

impl PublicKey for ElGamalPublic {
    /// Encrypts a byte slice using the ElGamal public key.
    ///
    /// This method takes a slice of bytes (`bytes`) as input and returns a `Result` containing either:
    /// * A tuple of two `UBig` values on success, representing the encrypted message (`c1`, `c2`).
    /// * An `Error::SmallKey` if the message is too large for the key.
    ///
    #[inline]
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        elgamal_encrypt(bytes, &self.prime, &self.alpha, &self.beta)
    }

    /// Encrypts a byte slice using the ElGamal public key dividing the slice into chunks prior and marshalling
    /// output blocks into one.
    ///
    /// This method takes a slice of bytes (`bytes`) as input and returns a `Result` containing either:
    /// * A tuple of two `UBig` values on success, representing the encrypted message (`c1`, `c2`).
    /// * An `Error::SmallKey` if the message is too large for the key.
    ///
    #[inline]
    fn encrypt_chunked(&self, bytes: &[u8], chunk_size: usize) -> Result<Vec<u8>> {
        elgamal_encrypt_chunked(bytes, &self.prime, &self.alpha, &self.beta, chunk_size)
    }

    #[inline]
    fn decrypt(&self, _message: &[u8]) -> Result<Vec<u8>> {
        unimplemented!()
    }
}
