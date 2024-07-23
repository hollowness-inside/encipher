use ibig::{IBig, UBig};
use ibig_ext::powmod::PowMod;

use crate::result::Error;
use crate::utils::{imod_inverse, unmarshal_bytes};
use crate::{keypair::PrivateKey, result::Result};

/// Private key for the ElGamal cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElGamalPrivate {
    pub prime: UBig,
    pub key: UBig,
}

impl PrivateKey for ElGamalPrivate {
    #[inline]
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        let cs = unmarshal_bytes(message);
        let c1 = cs[0].as_slice();
        let c2 = cs[1].as_slice();

        let c1 = UBig::from_be_bytes(c1);
        let c2 = UBig::from_be_bytes(c2);

        let c1_inv = imod_inverse(&c1, &self.prime);
        let c1_inv = c1_inv.powmod(self.key.clone(), &IBig::from(&self.prime));
        let c1_inv: UBig = c1_inv.try_into().map_err(|_| Error::MathError)?;

        let message = (c2 * c1_inv) % &self.prime;
        let bytes = message.to_be_bytes();

        Ok(bytes.to_vec())
    }
}
