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
    #[inline]
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        elgamal_encrypt(bytes, &self.prime, &self.alpha, &self.beta)
    }

    #[inline]
    fn encrypt_chunked(&self, bytes: &[u8], chunk_size: usize) -> Result<Vec<u8>> {
        elgamal_encrypt_chunked(bytes, &self.prime, &self.alpha, &self.beta, chunk_size)
    }

    #[inline]
    fn decrypt(&self, _message: &[u8]) -> Result<Vec<u8>> {
        unimplemented!()
    }

    #[inline]
    fn decrypt_chunked(&self, _message: &[u8], _chunk_size: usize) -> Result<Vec<u8>> {
        unimplemented!()
    }
}
