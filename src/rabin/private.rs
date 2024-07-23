use ibig::UBig;
use ibig_ext::sqrt::SquareRootMod;

use super::MAGIC;
use crate::result::Error;
use crate::utils::imod;
use crate::{keypair::PrivateKey, result::Result};

/// Private key for the Rabin cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RabinPrivate {
    /// First prime factor of the public modulus.
    pub prime_1: UBig,

    /// Second prime factor of the public modulus.
    pub prime_2: UBig,
}

impl PrivateKey for RabinPrivate {
    #[inline]
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        let p1 = &self.prime_1;
        let p2 = &self.prime_2;

        let (_, u, v) = p1.extended_gcd(p2);
        let message = UBig::from_le_bytes(message);
        let u = imod(&u, p2);
        let v = imod(&v, p2);

        let mp1: UBig = message.clone().square_root_mod(p1).expect("No root").0;
        let mp2: UBig = message.square_root_mod(p2).expect("No root").0;

        let n = p1 * p2;
        let x1 = &u * p1 * &mp2;
        let x2 = &v * p2 * &mp1;

        let m1: UBig = (&x1 + &x2) % &n;
        let m2: UBig = &n - &m1;
        let m3: UBig = (&x1 - &x2) % &n;
        let m4: UBig = n - &m3;

        for m in [m1, m2, m3, m4] {
            let m = m.to_le_bytes();
            if m.ends_with(MAGIC) {
                return Ok(m);
            }
        }

        Err(Error::MessageNotFound)
    }
}
