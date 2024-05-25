use ibig::UBig;
use ibig_ext::powmod::PowMod;

use crate::result::{Error, Result};

pub(super) fn rsa_encrypt(bytes: &[u8], exponent: &UBig, divisor: &UBig) -> Result<Vec<u8>> {
    let message = UBig::from_le_bytes(bytes);
    if &message >= divisor {
        return Err(Error::SmallKey);
    }

    let message = message.powmod(exponent.clone(), divisor);
    Ok(message.to_le_bytes())
}

pub(super) fn rsa_decrypt(message: &[u8], exponent: &UBig, divisor: &UBig) -> Result<Vec<u8>> {
    let message = UBig::from_le_bytes(message);
    let out = message.powmod(exponent.clone(), divisor);
    let bytes = out.to_le_bytes();

    Ok(bytes[0..bytes.len()].to_vec())
}
