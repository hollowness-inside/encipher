use ibig::UBig;

use super::basic::elgamal_encrypt;
use crate::{keypair::CryptoKey, result::Result};

/// Public key for the ElGamal cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElGamalPublic {
    pub prime: UBig,
    pub alpha: UBig,
    pub beta: UBig,
}

impl CryptoKey for ElGamalPublic {
    #[inline]
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        elgamal_encrypt(bytes, &self.prime, &self.alpha, &self.beta)
    }

    #[inline]
    fn decrypt(&self, _message: &[u8]) -> Result<Vec<u8>> {
        unimplemented!()
    }
}
