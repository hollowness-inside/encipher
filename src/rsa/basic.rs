use ibig::UBig;
use ibig_ext::powmod::PowMod;

use crate::result::{Error, Result};

pub(super) fn rsa_encrypt(bytes: &[u8], exponent: &UBig, divisor: &UBig) -> Result<Vec<u8>> {
    let mut bytes = bytes.to_vec();
    bytes.push(0x01);

    let message = UBig::from_le_bytes(&bytes);
    if &message >= divisor {
        return Err(Error::SmallKey);
    }

    let message = message.powmod(exponent.clone(), divisor);
    Ok(message.to_be_bytes())
}
