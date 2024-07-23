use ibig::UBig;
use ibig_ext::powmod::PowMod;

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
        let exponent = &self.exponent;
        let divisor = &self.divisor;
        let message = UBig::from_be_bytes(bytes);
        if &message >= divisor {
            return Err(Error::SmallKey);
        }

        let message = message.powmod(exponent.clone(), divisor);
        Ok(message.to_be_bytes())
    }
}
