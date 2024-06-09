use ibig::UBig;

use super::basic::rabin_encrypt;
use crate::{keypair::PublicKey, result::Result};

/// Public key for the Rabin cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RabinPublic {
    /// Public modulus used for encryption.
    pub divisor: UBig,
}

impl PublicKey for RabinPublic {
    fn verify<H: Fn(&[u8]) -> Vec<u8>>(
        &self,
        _expected: &[u8],
        _signed_data: &[u8],
        _hashf: &H,
    ) -> Result<bool> {
        todo!()
    }

    #[inline]
    fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        rabin_encrypt(message, &self.divisor)
    }
}
