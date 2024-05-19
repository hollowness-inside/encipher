use ibig::UBig;

use super::basic::rabin_encrypt;
use crate::{keypair::CryptoKey, result::Result};

/// Public key for the Rabin cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RabinPublic {
    /// Public modulus used for encryption.
    pub divisor: UBig,
}

impl CryptoKey for RabinPublic {
    #[inline]
    fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        rabin_encrypt(message, &self.divisor)
    }

    #[inline]
    fn decrypt_chunked(&self, _message: &[u8], _chunk_size: usize) -> Result<Vec<u8>> {
        unimplemented!()
    }

    #[inline]
    fn encrypt_chunked(&self, _message: &[u8], _chunk_size: usize) -> Result<Vec<u8>> {
        unimplemented!()
    }

    #[inline]
    fn decrypt(&self, _message: &[u8]) -> Result<Vec<u8>> {
        unimplemented!()
    }
}
