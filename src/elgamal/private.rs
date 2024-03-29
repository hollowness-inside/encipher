use ibig::UBig;
use ibig_ext::powmod::PowMod;

/// Private key for the ElGamal cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElGamalPrivate {
    pub prime: UBig,
    pub key: UBig,
}

impl ElGamalPrivate {
    /// Decrypts an ElGamal ciphertext using the private key.
    ///
    /// `message`: A slice containing the two ElGamal ciphertext components (`c1`, `c2`).
    ///
    /// Returns the decrypted message (`UBig`) on success.
    ///
    pub fn decrypt(&self, message: &[UBig; 2]) -> Vec<u8> {
        let [c1, c2] = message;

        let (_, c1_inv, _) = c1.extended_gcd(&self.prime);
        let c1_inv: UBig = c1_inv.try_into().expect("c1 inverse is negative");

        let message = (c2 * c1_inv.powmod(self.key.clone(), &self.prime)) % &self.prime;
        let bytes = message.to_le_bytes();
        bytes[0..bytes.len() - 1].to_vec()
    }
}
