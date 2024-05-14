use ibig::UBig;
use ibig_ext::sqrt::SquareRootMod;

use super::MAGIC;
use crate::{keypair::PrivateKey,
            result::{Error, Result}};

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
    /// Decrypts a Rabin-encrypted message using the private key.
    ///
    /// This function takes a `UBig` representing the encrypted message as input and returns an array
    /// of four `IBig` values, which are the possible decryptions due to Rabin's ambiguity.
    ///
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        let p1 = self.prime_1.clone();
        let p2 = self.prime_2.clone();

        let (_, u, v) = self.prime_1.extended_gcd(&self.prime_2);
        let message = UBig::from_be_bytes(message);
        let u = UBig::try_from(u).expect("Cannot convert u to UBig");
        let v = UBig::try_from(v).expect("Cannot convert v to UBig");

        let mp1: UBig = message
            .clone()
            .square_root_mod(&self.prime_1)
            .expect("No root")
            .0;

        let mp2: UBig = message.square_root_mod(&self.prime_2).expect("No root").0;

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

    fn encrypt(&self, _message: &[u8]) -> Result<Vec<u8>> {
        unimplemented!()
    }
}
