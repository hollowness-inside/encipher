use ibig::UBig;
use ibig_ext::powmod::PowMod;

use crate::result::{Error, Result};

/// Public key for the RSA algorithm.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RsaPublic {
    /// Public exponent used for encryption.
    pub exponent: UBig,

    /// Public modulus used for encryption.
    pub divisor: UBig,
}

impl RsaPublic {
    /// Encrypts a byte slice using the RSA public key.
    ///
    /// This method takes a slice of bytes (`bytes`) as input and returns a `Result` containing either:
    /// * The encrypted message as a `UBig` on success.
    /// * An `Error` indicating the reason for failure, specifically `Error::SmallKey` if the message is too large for the key.
    ///
    pub fn encrypt(&self, bytes: &[u8]) -> Result<UBig> {
        let message = UBig::from_le_bytes(bytes);
        if message > self.divisor {
            return Err(Error::SmallKey);
        }

        let exp = self.exponent.clone();
        Ok(message.powmod(exp, &self.divisor))
    }
}
