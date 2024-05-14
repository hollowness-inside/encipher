use ibig::{ubig, UBig};
use ibig_ext::powmod::PowMod;
use rand::Rng;

use crate::{result::{Error, Result},
            utils::{marshal_bytes, pad_message, unmarshal_bytes, unpad_message}};

pub(super) fn elgamal_encrypt_chunked(
    bytes: &[u8],
    prime: &UBig,
    alpha: &UBig,
    beta: &UBig,
    chunk_size: usize,
) -> Result<Vec<u8>> {
    let blocks: Vec<_> = pad_message(bytes, chunk_size)
        .chunks(chunk_size - 1)
        .map(|chunk| elgamal_encrypt(chunk, prime, alpha, beta))
        .collect::<Result<_>>()?;

    Ok(marshal_bytes(&blocks))
}

pub(super) fn elgamal_encrypt(
    bytes: &[u8],
    prime: &UBig,
    alpha: &UBig,
    beta: &UBig,
) -> Result<Vec<u8>> {
    let mut bytes = bytes.to_vec();
    bytes.push(0x01);

    let message = UBig::from_le_bytes(&bytes);
    if &message > prime {
        return Err(Error::SmallKey);
    }

    let mut rng = rand::thread_rng();
    let r = rng.gen_range(ubig!(0)..=prime - 2);

    let c1 = alpha.powmod(r.clone(), prime);
    let c2 = message * beta.powmod(r, prime);

    let c1_bytes = c1.to_be_bytes();
    let c2_bytes = c2.to_be_bytes();

    let output = vec![c1_bytes, c2_bytes];
    let output = marshal_bytes(&output);
    Ok(output)
}

pub(super) fn elgamal_decrypt(message: &[u8], prime: &UBig, key: &UBig) -> Result<Vec<u8>> {
    let cs = unmarshal_bytes(message);
    let c1 = cs[0].as_slice();
    let c2 = cs[1].as_slice();

    let c1 = UBig::from_be_bytes(c1);
    let c2 = UBig::from_be_bytes(c2);

    let (_, c1_inv, _) = c1.extended_gcd(prime);
    let c1_inv: UBig = c1_inv.try_into().map_err(|_| Error::MathError)?;

    let message = (c2 * c1_inv.powmod(key.clone(), prime)) % prime;
    let bytes = message.to_le_bytes();

    Ok(bytes[0..bytes.len() - 1].to_vec())
}

pub(super) fn elgamal_decrypt_chunked(
    message: &[u8],
    prime: &UBig,
    key: &UBig,
    chunk_size: usize,
) -> Result<Vec<u8>> {
    let bytes: Vec<u8> = unmarshal_bytes(message)
        .iter()
        .map(|chunk| elgamal_decrypt(chunk, prime, key))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();

    Ok(unpad_message(&bytes, chunk_size).to_vec())
}
