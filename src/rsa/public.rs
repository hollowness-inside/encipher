use ibig::UBig;
use ibig_ext::powmod::PowMod;

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

impl Verifier for RsaPublic {
    fn verify(
        &self,
        expected: &[u8],
        signed_data: &[u8],
        hashf: fn(&[u8]) -> Vec<u8>,
    ) -> Result<bool> {
        let expected_hash = hashf(expected);

        let mut out = UBig::from_le_bytes(signed_data)
            .powmod(self.exponent.clone(), &self.divisor)
            .to_le_bytes()
            .to_vec();
        out.resize(expected_hash.len(), 0);

        Ok(out.eq(&expected_hash))
    }
}
