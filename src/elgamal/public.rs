use ibig::{ubig, UBig};
use ibig_ext::powmod::PowMod;
use rand::Rng;

use crate::{keypair::PublicKey,
            result::{Error, Result},
            utils::marshal_bytes};

/// Public key for the ElGamal cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElGamalPublic {
    pub prime: UBig,
    pub alpha: UBig,
    pub beta: UBig,
}

impl PublicKey for ElGamalPublic {
    /// Encrypts a byte slice using the ElGamal public key.
    ///
    /// This method takes a slice of bytes (`bytes`) as input and returns a `Result` containing either:
    /// * A tuple of two `UBig` values on success, representing the encrypted message (`c1`, `c2`).
    /// * An `Error::SmallKey` if the message is too large for the key.
    ///
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
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

        let c1_bytes = c1.to_be_bytes();
        let c2_bytes = c2.to_be_bytes();

        let output = vec![c1_bytes, c2_bytes];
        let output = marshal_bytes(&output);
        Ok(output)
    }
}
