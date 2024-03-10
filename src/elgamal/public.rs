use ibig::{ubig, UBig};
use ibig_ext::powmod::PowMod;
use rand::Rng;

use crate::result::{Error, Result};

/// Public key for the ElGamal cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElGamalPublic {
    pub prime: UBig,
    pub alpha: UBig,
    pub beta: UBig,
}

impl ElGamalPublic {
    /// Encrypts a byte slice using the ElGamal public key.
    ///
    /// This method takes a slice of bytes (`bytes`) as input and returns a `Result` containing either:
    /// * A tuple of two `UBig` values on success, representing the encrypted message (`c1`, `c2`).
    /// * An `Error::SmallKey` if the message is too large for the key.
    ///
    pub fn encrypt(&self, bytes: &[u8]) -> Result<[UBig; 2]> {
        let mut bytes = bytes.to_vec();
        bytes.push(0x01);

        let message = UBig::from_le_bytes(&bytes);
        if message > self.prime {
            return Err(Error::SmallKey);
        }

        let mut rng = rand::thread_rng();
        let r = rng.gen_range(ubig!(0)..=&self.prime - 2);

        let c1 = self.alpha.powmod(r.clone(), &self.prime);
        let c2 = message * self.beta.powmod(r, &self.prime);

        Ok([c1, c2])
    }
}
