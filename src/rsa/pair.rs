use ibig::{ubig, UBig};
use ibig_ext::prime_gen::gen_sized_prime;

use super::{RsaPrivate, RsaPublic};
use crate::{keypair::{KeyPair, PrivateKey, PublicKey},
            result::Result};

/// An RSA key pair for encryption and decryption.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RsaKeyPair {
    /// The public key for encryption.
    public: RsaPublic,

    /// The private  key for decryption.
    private: RsaPrivate,
}

impl KeyPair for RsaKeyPair {
    type Public = RsaPublic;
    type Private = RsaPrivate;
    /// Generates a new RSA key pair with the specified bit length and persistence level.
    ///
    /// * `bit_length`: The desired bit length for the keys in the pair.
    /// * `persistence`: The number of iterations for checking numbers for primality.
    ///
    /// Returns the newly generated `RsaKeyPair` instance.
    fn generate(bit_length: usize, persistence: usize) -> Self {
        let p = gen_sized_prime(bit_length, persistence);
        let q = gen_sized_prime(bit_length, persistence);

        let n = &p * &q;
        let totient = (&p - 1) * (&q - 1);

        let e: UBig = ubig!(2).pow(16) + 1;
        let (_, d, _) = e.extended_gcd(&totient);
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

    #[inline]
    fn public(&self) -> &Self::Public {
        &self.public
    }

    #[inline]
    fn private(&self) -> &Self::Private {
        &self.private
    }
}

impl RsaKeyPair {
    /// Creates a new RSA key pair with a default persistence level of 10.
    #[inline]
    pub fn new(bit_length: usize) -> Self {
        Self::generate(bit_length, 10)
    }
}

impl PrivateKey for RsaKeyPair {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.private.sign(message)
    }

    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.private.decrypt(message)
    }
}

impl PublicKey for RsaKeyPair {
    fn verify(&self, expected: &[u8], message: &[u8]) -> Result<bool> {
        self.public.verify(expected, message)
    }

    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        self.public.encrypt(bytes)
    }
}
