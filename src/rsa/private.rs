use ibig::UBig;
use powmod::PowMod;

#[derive(Debug)]
pub struct RsaPrivate {
    pub private_exponent: UBig,

    pub prime_1: UBig,
    pub prime_2: UBig,
}

impl RsaPrivate {
    pub fn decrypt(&self, message: &UBig) -> UBig {
        let exp = self.private_exponent.clone();
        let div = &self.prime_1 * &self.prime_2;

        message.powmod(exp, &div)
    }
}