use ibig::{ubig, UBig};
use powmod::PowMod;

use crate::result::{Error, Result};

use super::MAGIC;

/// Public key for the Rabin cryptosystem.
#[derive(Debug)]
pub struct RabinPublic {
    /// Public modulus used for encryption.
    pub divisor: UBig,
}

impl RabinPublic {
    /// Encrypts a byte slice using the Rabin public key.
    ///
    /// This method takes a slice of bytes (`message`) as input and returns a `Result` containing either:
    /// * The encrypted message as a `UBig` on success.
    /// * An `Error::SmallKey` if the message is too large for the key.
    ///
    /// * **Note:** This function performs Rabin encryption with message padding using the constant `MAGIC`.
    /// The specific value of `MAGIC` is defined in the `MAGIC` constant.
    pub fn encrypt(&self, message: &[u8]) -> Result<UBig> {
        let mut message = message.to_vec();
        message.extend(MAGIC);

        let message = UBig::from_le_bytes(&message);

        if message >= self.divisor {
            return Err(Error::SmallKey);
        }

        Ok(message.powmod(ubig!(2), &self.divisor))
    }
}
