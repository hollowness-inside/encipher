use ibig::UBig;
use ibig_ext::powmod::PowMod;

use crate::{result::{Error, Result},
            utils::{marshal_bytes, pad_message, unmarshal_bytes}};

pub(super) fn rsa_encrypt_chunked(
    bytes: &[u8],
    exponent: &UBig,
    divisor: &UBig,
    chunk_size: usize,
) -> Result<Vec<u8>> {
    let content: Vec<Vec<_>> = pad_message(bytes, chunk_size)
        .chunks(chunk_size - 1)
        .map(|chunk| rsa_encrypt(chunk, exponent, divisor))
        .collect::<Result<_>>()?;

    Ok(marshal_bytes(&content))
}

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

pub(super) fn rsa_decrypt(message: &[u8], exponent: &UBig, divisor: &UBig) -> Result<Vec<u8>> {
    let message = UBig::from_be_bytes(message);
    let out = message.powmod(exponent.clone(), divisor);
    let bytes = out.to_le_bytes();

    Ok(bytes[0..bytes.len() - 1].to_vec())
}

pub(super) fn rsa_decrypt_marshalled(
    message: &[u8],
    exponent: &UBig,
    divisor: &UBig,
) -> Result<Vec<u8>> {
    Ok(unmarshal_bytes(message)
        .iter()
        .map(|chunk| rsa_decrypt(chunk, exponent, divisor))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect())
}
