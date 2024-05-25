use ibig::UBig;

use super::basic::rsa_encrypt;
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

// impl CryptoKey for RsaPublic {
//     #[inline]
//     fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
//         rsa_decrypt(message, &self.exponent, &self.divisor)
//     }
// }

impl PublicKey for RsaPublic {
    fn verify(&self, _message: &[u8]) -> Result<bool> {
        unimplemented!()
    }

    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        rsa_encrypt(bytes, &self.exponent, &self.divisor)
    }
}
