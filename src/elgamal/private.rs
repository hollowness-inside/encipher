use ibig::ops::RemEuclid;
use ibig::{ubig, IBig, UBig};
use ibig_ext::powmod::PowMod;
use rand::Rng;

use super::basic::elgamal_decrypt;
use crate::{keypair::PrivateKey, result::Result, utils::marshal_bytes};

/// Private key for the ElGamal cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElGamalPrivate {
    pub alpha: UBig,
    pub beta: UBig,
    pub prime: UBig,
    pub key: UBig,
}

impl PrivateKey for ElGamalPrivate {
    fn sign<H: Fn(&[u8]) -> Vec<u8>>(&self, bytes: &[u8], hashf: &H) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();

        let (r, r_inv) = loop {
            let candidate = rng.gen_range(ubig!(1)..&self.prime - 1);

            let (gcd, r_inv, _) = candidate.extended_gcd(&(&self.prime - 1));

            if gcd == ubig!(1) {
                let r_inv = r_inv.rem_euclid(IBig::from(&self.prime - 1));
                let r_inv = UBig::try_from(r_inv).unwrap();
                break (candidate, r_inv);
            }
        };

        let sigma = self.alpha.powmod(r.clone(), &self.prime);

        let msg_hash = hashf(bytes);
        let msg_hash = UBig::from_be_bytes(&msg_hash);

        let delta: UBig = ((&msg_hash - &self.key * &sigma) * &r_inv) % (&self.prime - 1);

        Ok(marshal_bytes(&vec![
            sigma.to_le_bytes(),
            delta.to_le_bytes(),
        ]))
    }

    #[inline]
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        elgamal_decrypt(message, &self.prime, &self.key)
    }
}
