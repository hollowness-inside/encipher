use ibig::{ubig, UBig};
use ibig_ext::{powmod::PowMod, sqrt::SquareRootMod};

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

pub(super) fn rabin_decrypt(message: &[u8], prime_1: &UBig, prime_2: &UBig) -> Result<Vec<u8>> {
    let p1 = prime_1.clone();
    let p2 = prime_2.clone();

    let (_, u, v) = prime_1.extended_gcd(prime_2);
    let message = UBig::from_be_bytes(message);
    let u = UBig::try_from(u).expect("Cannot convert u to UBig");
    let v = UBig::try_from(v).expect("Cannot convert v to UBig");

    let mp1: UBig = message.clone().square_root_mod(prime_1).expect("No root").0;

    let mp2: UBig = message.square_root_mod(prime_2).expect("No root").0;

    let n = &p1 * &p2;
    let m1: UBig = (&u * &p1 * &mp2 + &v * &p2 * &mp1) % &n;
    let m2: UBig = &n - &m1;
    let m3: UBig = (&u * &p1 * &mp2 - &v * &p2 * &mp1) % &n;
    let m4: UBig = &n - &m3;

    for m in [m1, m2, m3, m4] {
        let m = m.to_be_bytes();
        if m.ends_with(MAGIC) {
            return Ok(m);
        }
    }

    Err(Error::MessageNotFound)
}
