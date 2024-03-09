use ibig::UBig;
use ibig_ext::powmod::PowMod;

/// Private key for the RSA algorithm.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RsaPrivate {
    /// Private exponent used for decryption.
    pub exponent: UBig,

    /// First prime factor of the public modulus.
    pub prime_1: UBig,

    /// Second prime factor of the public modulus.
    pub prime_2: UBig,
}

impl RsaPrivate {
    /// Decrypts a message received using the corresponding RSA public key.
    ///
    /// This method takes a message as a `UBig` and returns the decrypted message as a `UBig`.
    ///
    pub fn decrypt(&self, message: &UBig) -> UBig {
        let exp = self.exponent.clone();
        let div = &self.prime_1 * &self.prime_2;

        message.powmod(exp, &div)
    }
}
