use ibig::UBig;

use super::basic::elgamal_encrypt;
use crate::{keypair::PublicKey, result::Result};

/// Public key for the ElGamal cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElGamalPublic {
    pub prime: UBig,
    pub alpha: UBig,
    pub beta: UBig,
}

// impl CryptoKey for ElGamalPublic {
//     #[inline]
//     fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
//         let cs = unmarshal_bytes(message);
//         let sigma = cs[0].as_slice();
//         let delta = cs[1].as_slice();

//         let sigma = UBig::from_be_bytes(sigma);
//         let delta = UBig::from_be_bytes(delta);

//         let m = self.beta.powmod(sigma.clone(), &self.prime) * sigma.powmod(delta, &self.prime);
//         Ok(m.to_le_bytes())
//     }
// }

impl PublicKey for ElGamalPublic {
    fn verify(&self, expected: &[u8], _signed_data: &[u8]) -> Result<bool> {
        todo!()
    }

    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        elgamal_encrypt(bytes, &self.prime, &self.alpha, &self.beta)
    }
}
