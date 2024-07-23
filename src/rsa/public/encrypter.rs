use ibig::UBig;
use ibig_ext::powmod::PowMod;

#[cfg(signatures)]
use crate::keypair::Verifier;

use crate::result::Error;
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
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let message = UBig::from_le_bytes(bytes);
        if message >= self.divisor {
            return Err(Error::SmallKey);
        }

        let message = message.powmod(self.exponent.clone(), &self.divisor);
        Ok(message.to_le_bytes())
    }
}