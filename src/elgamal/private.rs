use ibig::UBig;
use ibig_ext::powmod::PowMod;

use crate::{keypair::PrivateKey,
            result::{Error, Result},
            utils::unmarshal_bytes};

use super::basic::{elgamal_decrypt, elgamal_encrypt};

/// Private key for the ElGamal cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElGamalPrivate {
    pub prime: UBig,
    pub key: UBig,
}

impl PrivateKey for ElGamalPrivate {
    /// Decrypts an ElGamal ciphertext using the private key.
    ///
    /// `message`: A slice containing the two ElGamal ciphertext components (`c1`, `c2`).
    ///
    /// Returns the decrypted message (`UBig`) on success.
    ///
    #[inline]
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        elgamal_decrypt(message, &self.prime, &self.key)
    }

    fn encrypt(&self, _message: &[u8]) -> Result<Vec<u8>> {
        unimplemented!()
    }
}
