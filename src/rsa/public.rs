use ibig::UBig;
use ibig_ext::powmod::PowMod;

use crate::keypair::PublicKey;
use crate::result::{Error, Result};

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
    /// Encrypts a byte slice using the RSA public key.
    ///
    /// This method takes a slice of bytes (`bytes`) as input and returns a `Result` containing either:
    /// * The encrypted message on success.
    /// * An `Error` indicating the reason for failure, specifically `Error::SmallKey` if the message is too large for the key.
    ///
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let mut bytes = bytes.to_vec();
        bytes.push(0x01);

        let message = UBig::from_le_bytes(&bytes);
        if message >= self.divisor {
            return Err(Error::SmallKey);
        }

        let exp = self.exponent.clone();
        let message = message.powmod(exp, &self.divisor);
        Ok(message.to_be_bytes())
    }
}