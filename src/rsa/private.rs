use ibig::UBig;
use ibig_ext::powmod::PowMod;

use crate::keypair::Signer;
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
        let message = UBig::from_le_bytes(message);
        let out = message.powmod(self.exponent.clone(), &div);

        Ok(out.to_le_bytes())
    }
}

impl Signer for RsaPrivate {
    fn sign(&self, data: &[u8], hashf: fn(&[u8]) -> Vec<u8>) -> Result<Vec<u8>> {
        let divisor = &self.prime_1 * &self.prime_2;
        let data_hash = UBig::from_le_bytes(&hashf(data));

        let message = data_hash.powmod(self.exponent.clone(), &divisor);
        Ok(message.to_le_bytes())
    }
}
