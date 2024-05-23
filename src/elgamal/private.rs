use ibig::{ubig, UBig};
use ibig_ext::powmod::PowMod;
use rand::Rng;

use super::basic::elgamal_decrypt;
use crate::{keypair::CryptoKey,
            result::{Error, Result},
            utils::marshal_bytes};

/// Private key for the ElGamal cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElGamalPrivate {
    pub alpha: UBig,
    pub beta: UBig,
    pub prime: UBig,
    pub key: UBig,
}

impl CryptoKey for ElGamalPrivate {
    #[inline]
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        elgamal_decrypt(message, &self.prime, &self.key)
    }

    #[inline]
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let message = UBig::from_le_bytes(&bytes);
        if message > self.prime {
            return Err(Error::SmallKey);
        }

        let r = rand::thread_rng().gen_range(ubig!(1)..&self.prime - 2);
        let (_, r_inv, _) = r.extended_gcd(&(&self.prime - 1));
        let r_inv: UBig = r_inv.try_into().map_err(|_| Error::MathError)?;

        let sigma = self.alpha.powmod(r.clone(), &self.prime);
        let delta: UBig = ((message - &self.alpha * &sigma) * r_inv) % (&self.prime - 1);

        Ok(marshal_bytes(&vec![
            sigma.to_le_bytes(),
            delta.to_le_bytes(),
        ]))
    }
}
