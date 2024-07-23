use ibig::{ubig, UBig};
use ibig_ext::powmod::PowMod;
use rand::Rng;

use crate::result::Error;
use crate::utils::{marshal_bytes, unmarshal_bytes};
use crate::Verifier;
use crate::{keypair::PublicKey, result::Result};

/// Public key for the ElGamal cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElGamalPublic {
    pub prime: UBig,
    pub alpha: UBig,
    pub beta: UBig,
}

impl PublicKey for ElGamalPublic {
    #[inline]
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let message = UBig::from_le_bytes(bytes);
        if message >= self.prime {
            return Err(Error::SmallKey);
        }

        let mut rng = rand::thread_rng();
        let r = rng.gen_range(ubig!(0)..=&self.prime - 2);

        let c1 = self.alpha.powmod(r.clone(), &self.prime);
        let c2 = message * self.beta.powmod(r, &self.prime);

        let c1_bytes = c1.to_le_bytes();
        let c2_bytes = c2.to_le_bytes();

        let output = vec![c1_bytes, c2_bytes];
        let output = marshal_bytes(&output);
        Ok(output)
    }
}

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
