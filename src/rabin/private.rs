use ibig::UBig;

use super::basic::rabin_decrypt;
use crate::{keypair::PrivateKey, result::Result};

/// Private key for the Rabin cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RabinPrivate {
    /// First prime factor of the public modulus.
    pub prime_1: UBig,

    /// Second prime factor of the public modulus.
    pub prime_2: UBig,
}

impl PrivateKey for RabinPrivate {
    /// Decrypts a Rabin-encrypted message using the private key.
    ///
    /// This function takes a `UBig` representing the encrypted message as input and returns an array
    /// of four `IBig` values, which are the possible decryptions due to Rabin's ambiguity.
    ///
    #[inline]
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        rabin_decrypt(message, &self.prime_1, &self.prime_2)
    }

    #[inline]
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
