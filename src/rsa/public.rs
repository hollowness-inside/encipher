use ibig::UBig;
use powmod::PowMod;

use crate::result::{Error, Result};

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
