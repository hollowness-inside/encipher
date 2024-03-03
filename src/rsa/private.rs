use ibig::UBig;
use powmod::PowMod;

/// Private key for the RSA algorithm.
#[derive(Debug)]
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
