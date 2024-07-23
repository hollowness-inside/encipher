mod marshal;
mod to_bytes;

use ibig::ops::RemEuclid;
use ibig::{IBig, UBig};
pub(crate) use marshal::{marshal_bytes, unmarshal_bytes};

pub(crate) fn imod_inverse(a: &UBig, m: &UBig) -> IBig {
    a.extended_gcd(m).1
}

pub(crate) fn imod(a: &IBig, m: &UBig) -> UBig {
    UBig::try_from(a.rem_euclid(IBig::from(m))).unwrap()
}

#[allow(dead_code)]
pub(crate) fn mod_sub(a: &UBig, b: &UBig, m: &UBig) -> UBig {
    let a = a % m;
    let b = b % m;

    let diff = match a > b {
        true => a - b,
        false => a + (m - b),
    };

    diff % m
}

#[cfg(test)]
mod tests;
