use ibig::UBig;
use ibig_ext::powmod::PowMod;

use crate::result::Result;
use crate::signatures::Verifier;
use crate::utils::unmarshal_bytes;

use super::ElGamalPublic;

impl Verifier for ElGamalPublic {
    fn verify(
        &self,
        expected: &[u8],
        signed_data: &[u8],
        hashf: fn(&[u8]) -> Vec<u8>,
    ) -> Result<bool> {
        let sd = unmarshal_bytes(signed_data);
        let sigma = UBig::from_le_bytes(&sd[0]);
        let delta = UBig::from_le_bytes(&sd[1]);

        let lhs = {
            let a = self.beta.powmod(sigma.clone(), &self.prime);
            let b = sigma.powmod(delta, &self.prime);
            (a * b) % &self.prime
        };

        let rhs = {
            let hash = UBig::from_le_bytes(&hashf(expected));
            self.alpha.powmod(hash, &self.prime)
        };

        Ok(lhs == rhs)
    }
}
