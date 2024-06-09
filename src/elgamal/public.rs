use ibig::UBig;
use ibig_ext::powmod::PowMod;

use super::basic::elgamal_encrypt;
use crate::{keypair::PublicKey, result::Result, utils::unmarshal_bytes};

/// Public key for the ElGamal cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElGamalPublic {
    pub prime: UBig,
    pub alpha: UBig,
    pub beta: UBig,
}

impl PublicKey for ElGamalPublic {
    fn verify<H: Fn(&[u8]) -> Vec<u8>>(
        &self,
        expected: &[u8],
        signed_data: &[u8],
        hashf: &H,
    ) -> Result<bool> {
        let sd = unmarshal_bytes(signed_data);
        let sigma = UBig::from_be_bytes(&sd[0]);
        let delta = UBig::from_be_bytes(&sd[1]);

        let lhs = (self.beta.powmod(sigma.clone(), &self.prime) * sigma.powmod(delta, &self.prime))
            % &self.prime;

        let msg_hash = hashf(expected);
        let msg_hash = UBig::from_be_bytes(&msg_hash);

        let rhs = self.alpha.powmod(msg_hash, &self.prime);

        Ok(lhs == rhs)
    }

    #[inline]
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        elgamal_encrypt(bytes, &self.prime, &self.alpha, &self.beta)
    }
}
