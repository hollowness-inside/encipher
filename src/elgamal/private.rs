use ibig::UBig;
use ibig_ext::powmod::PowMod;

use crate::{keypair::PrivateKey, utils::unmarshal_bytes};

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
    fn decrypt(&self, message: &[u8]) -> Vec<u8> {
        let cs = unmarshal_bytes(message);
        let c1 = cs[0].as_slice();
        let c2 = cs[1].as_slice();

        let c1 = UBig::from_be_bytes(c1);
        let c2 = UBig::from_be_bytes(c2);

        let (_, c1_inv, _) = c1.extended_gcd(&self.prime);
        let c1_inv: UBig = c1_inv.try_into().expect("c1 inverse is negative");

        let message = (c2 * c1_inv.powmod(self.key.clone(), &self.prime)) % &self.prime;
        let bytes = message.to_le_bytes();
        bytes[0..bytes.len() - 1].to_vec()
    }
}
