use ibig::{ubig, UBig};
use ibig_ext::powmod::PowMod;

use super::MAGIC;
use crate::result::{Error, Result};

pub(super) fn rabin_encrypt(message: &[u8], divisor: &UBig) -> Result<Vec<u8>> {
    let mut message = message.to_vec();
    message.extend(MAGIC);

    let message = UBig::from_le_bytes(&message);
    if &message >= divisor {
        return Err(Error::SmallKey);
    }

    let message = message.powmod(ubig!(2), divisor);
    Ok(message.to_be_bytes())
}
