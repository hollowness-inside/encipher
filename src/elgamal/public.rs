use ibig::{ubig, UBig};
use powmod::PowMod;
use rand::Rng;

use crate::result::{Error, Result};

#[derive(Debug)]
pub struct ElGamalPublic {
    pub prime: UBig,
    pub alpha: UBig,
    pub beta: UBig,
}

impl ElGamalPublic {
    pub fn encrypt(&self, bytes: &[u8]) -> Result<[UBig; 2]> {
        let message = UBig::from_le_bytes(bytes);
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
