use crate::result::{Error, Result};

use ibig::{ubig, UBig};
use powmod::PowMod;

#[derive(Debug)]
pub struct RsaPublic {
    pub exponent: UBig,
    pub divisor: UBig,
}

impl RsaPublic {
    pub fn encrypt(&self, bytes: &[u8]) -> Result<UBig> {
        let message = UBig::from_le_bytes(bytes);
        if message > self.divisor {
            return Err(Error::SmallKey);
        }

        let exp = self.exponent.clone();
        Ok(message.powmod(exp, &self.divisor))
    }
}

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

#[derive(Debug)]
pub struct RsaKeyPair(pub RsaPublic, pub RsaPrivate);

impl RsaKeyPair {
    pub fn new(bit_length: usize, persistence: usize) -> Self {
        let p = prime_gen::gen_sized_prime(bit_length, persistence);
        let q = prime_gen::gen_sized_prime(bit_length, persistence);

        let n = &p * &q;
        let totient = (&p - 1) * (&q - 1);

        let e: UBig = ubig!(2).pow(16) + 1;
        let (_, d, _) = e.extended_gcd(&totient);
        let d: UBig = d.try_into().expect("Cannot convert d to UBig");

        Self(
            RsaPublic {
                exponent: e,
                divisor: n,
            },
            RsaPrivate {
                private_exponent: d.clone(),
                prime_1: p.clone(),
                prime_2: q.clone(),
            },
        )
    }
}
