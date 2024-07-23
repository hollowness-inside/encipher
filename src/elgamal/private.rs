use ibig::{ops::RemEuclid, ubig, IBig, UBig};
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
    #[inline]
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        elgamal_decrypt(message, &self.prime, &self.key)
    }
}

fn sub_mod(a: &UBig, b: &UBig, m: &UBig) -> UBig {
    if a > b {
        (a - b) % m
    } else {
        (b - a) % m
    }
}
