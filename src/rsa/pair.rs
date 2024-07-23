use ibig::{ops::RemEuclid, ubig, IBig, UBig};
use ibig_ext::prime_gen::gen_sized_prime;

use super::{RsaPrivate, RsaPublic};
use crate::{result::Result, PrivateKey, PublicKey};

/// An RSA key pair for encryption and decryption.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RsaKeyPair {
    /// The public key for encryption.
    pub public: RsaPublic,

    /// The private  key for decryption.
    pub private: RsaPrivate,
}

impl RsaKeyPair {
    /// Generates a new RSA key pair with the specified bit length and persistence level.
    ///
    /// * `bit_length`: The desired bit length for the keys in the pair.
    /// * `persistence`: The number of iterations for checking numbers for primality.
    ///
    /// Returns the newly generated `RsaKeyPair` instance.
    pub fn new(bit_length: usize, persistence: usize) -> Self {
        let p = gen_sized_prime(bit_length, persistence);
        let q = gen_sized_prime(bit_length, persistence);

        let n = &p * &q;
        let totient = (&p - 1) * (&q - 1);

        let e: UBig = ubig!(2).pow(16) + 1;
        let (_, d, _) = e.extended_gcd(&totient);
        let d = d.rem_euclid(IBig::from(totient));
        let d: UBig = d.try_into().expect("Cannot convert d to UBig");

        Self {
            public: RsaPublic {
                exponent: e,
                divisor: n,
            },
            private: RsaPrivate {
                exponent: d,
                prime_1: p,
                prime_2: q,
            },
        }
    }
}

impl PrivateKey for RsaKeyPair {
    #[inline]
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.private.decrypt(message)
    }
}

impl PublicKey for RsaKeyPair {
    #[inline]
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        self.public.encrypt(bytes)
    }
}
