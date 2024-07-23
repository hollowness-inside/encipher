use ibig::{ubig, UBig};
use ibig_ext::powmod::PowMod;

use super::MAGIC;
use crate::result::Error;
use crate::{keypair::PublicKey, result::Result};

/// Public key for the Rabin cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RabinPublic {
    /// Public modulus used for encryption.
    pub divisor: UBig,
}

impl PublicKey for RabinPublic {
    #[inline]
    fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut message = message.to_vec();
        message.extend(MAGIC);

        let message = UBig::from_le_bytes(&message);
        if message >= self.divisor {
            return Err(Error::SmallKey);
        }

        let message = message.powmod(ubig!(2), &self.divisor);
        Ok(message.to_le_bytes())
    }
}
