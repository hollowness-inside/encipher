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
    /// Encrypts a byte slice using the Rabin public key.
    ///
    /// This method takes a slice of bytes (`message`) as input and returns a `Result` containing either:
    /// * The encrypted message as a `UBig` on success.
    /// * An `Error::SmallKey` if the message is too large for the key.
    ///
    /// * **Note:** This function performs Rabin encryption with message padding using the constant `MAGIC`.
    /// The specific value of `MAGIC` is defined in the `MAGIC` constant.
    ///
    #[inline]
    fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        rabin_encrypt(message, &self.divisor)
    }
}
