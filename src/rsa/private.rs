use ibig::UBig;
use ibig_ext::powmod::PowMod;

use crate::keypair::PrivateKey;
use crate::result::Result;

/// Private key for the RSA algorithm.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RsaPrivate {
    /// Private exponent used for decryption.
    pub exponent: UBig,

    /// First prime factor of the public modulus.
    pub prime_1: UBig,

    /// Second prime factor of the public modulus.
    pub prime_2: UBig,
}

impl PrivateKey for RsaPrivate {
    /// Decrypts a message received using the corresponding RSA public key.
    ///
    /// This method takes a message as a `UBig` and returns the decrypted message as a `UBig`.
    ///
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        let exp = self.exponent.clone();
        let div = &self.prime_1 * &self.prime_2;

        let message = UBig::from_be_bytes(message);
        let out = message.powmod(exp, &div);
        let bytes = out.to_le_bytes();
        
        Ok(bytes[0..bytes.len() - 1].to_vec())
    }
}
