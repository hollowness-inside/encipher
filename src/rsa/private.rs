use ibig::UBig;
use ibig_ext::powmod::PowMod;

use crate::{keypair::PrivateKey, result::Result};

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
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        let div = &self.prime_1 * &self.prime_2;
        let exponent = &self.exponent;
        let divisor = &div;
        let message = UBig::from_be_bytes(message);
        let out = message.powmod(exponent.clone(), divisor);

        Ok(out.to_be_bytes())
    }
}
