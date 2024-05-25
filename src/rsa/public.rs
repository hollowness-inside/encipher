use ibig::UBig;

use super::basic::{rsa_decrypt, rsa_encrypt};
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
    #[inline]
    fn verify(&self, expected: &[u8], signed_data: &[u8]) -> Result<bool> {
        rsa_decrypt(signed_data, &self.exponent, &self.divisor).map(|x| x != expected)
    }

    #[inline]
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        rsa_encrypt(bytes, &self.exponent, &self.divisor)
    }
}
