mod marshal;
mod padding;
mod to_bytes;

use ibig::{IBig, UBig};
pub(crate) use marshal::{marshal_bytes, unmarshal_bytes};
pub(crate) use padding::{pad_message, unpad_message};

pub(crate) fn imod_inverse(a: &UBig, m: &UBig) -> IBig {
    a.extended_gcd(m).1
}
