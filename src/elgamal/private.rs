use ibig::{ubig, IBig, UBig};
use ibig_ext::powmod::PowMod;
use rand::Rng;

use crate::result::Error;
use crate::utils::{imod, imod_inverse, marshal_bytes, mod_sub, unmarshal_bytes};
use crate::Signer;
use crate::{keypair::PrivateKey, result::Result};

/// Private key for the ElGamal cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElGamalPrivate {
    pub alpha: UBig,
    pub prime: UBig,
    pub key: UBig,
}

impl PrivateKey for ElGamalPrivate {
    #[inline]
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        let cs = unmarshal_bytes(message);
        let c1 = cs[0].as_slice();
        let c2 = cs[1].as_slice();

        let c1 = UBig::from_le_bytes(c1);
        let c2 = UBig::from_le_bytes(c2);

        let c1_inv = imod_inverse(&c1, &self.prime);
        let c1_inv = c1_inv.powmod(self.key.clone(), &IBig::from(&self.prime));
        let c1_inv: UBig = c1_inv.try_into().map_err(|_| Error::MathError)?;

        let message = (c2 * c1_inv) % &self.prime;
        let bytes = message.to_le_bytes();

        Ok(bytes.to_vec())
    }
}

impl Signer for ElGamalPrivate {
    fn sign(&self, data: &[u8], hashf: fn(&[u8]) -> Vec<u8>) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let modulo: UBig = &self.prime - 1;

        let (r, r_inv) = loop {
            let r = rng.gen_range(ubig!(2)..modulo.clone());
            let (gcd, r_inv, _) = r.extended_gcd(&modulo);
            if gcd == ubig!(1) {
                let r_inv = imod(&r_inv, &modulo);
                break (r, r_inv);
            }
        };

        let sigma = self.alpha.powmod(r, &self.prime);
        let delta = {
            let a = UBig::from_le_bytes(&hashf(data));
            let b = &self.key * &sigma;

            (mod_sub(&a, &b, &modulo) * r_inv) % modulo
        };

        let sigma_bytes = sigma.to_le_bytes();
        let delta_bytes = delta.to_le_bytes();

        Ok(marshal_bytes(&vec![sigma_bytes, delta_bytes]))
    }
}
