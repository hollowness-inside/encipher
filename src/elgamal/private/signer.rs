use ibig::{ubig, UBig};
use ibig_ext::powmod::PowMod;
use rand::Rng;

use crate::signatures::Signer;
use crate::result::Result;
use crate::utils::{imod, marshal_bytes, mod_sub};

use super::ElGamalPrivate;

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
