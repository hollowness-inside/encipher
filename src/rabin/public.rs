use ibig::{ubig, UBig};
use powmod::PowMod;

use crate::result::{Error, Result};

use super::MAGIC;

#[derive(Debug)]
pub struct RabinPublic {
    pub divisor: UBig,
}

impl RabinPublic {
    pub fn encrypt(&self, message: &[u8]) -> Result<UBig> {
        let mut message = message.to_vec();
        message.extend(MAGIC);

        let message = UBig::from_le_bytes(&message);

        if message >= self.divisor {
            return Err(Error::SmallKey);
        }

        Ok(message.powmod(ubig!(2), &self.divisor))
    }
}
