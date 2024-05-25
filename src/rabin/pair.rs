use ibig::UBig;
use ibig_ext::prime_gen::gen_sized_prime;

use super::{private::RabinPrivate, public::RabinPublic};
use crate::{keypair::{KeyPair, PrivateKey, PublicKey},
            result::Result};

/// A key pair for the Rabin cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RabinKeyPair {
    /// The public key for encryption.
    public: RabinPublic,

    /// The private key for decryption.
    private: RabinPrivate,
}

impl KeyPair for RabinKeyPair {
    type Public = RabinPublic;
    type Private = RabinPrivate;
    /// Generates a new Rabin key pair with the specified bit length and persistence level.
    ///
    /// * `bit_length`: The desired bit length for the keys in the pair (increased by 8 for internal logic).
    /// * `persistence`: The number of iterations for checking numbers for primality.
    ///
    /// Returns a newly generated `RabinKeyPair` instance.
    fn generate(mut bit_length: usize, persistence: usize) -> Self {
        bit_length += 8;

        let p = gen_prime(bit_length, persistence);
        let q = gen_prime(bit_length, persistence);
        let n = &p * &q;

        Self {
            public: RabinPublic { divisor: n },
            private: RabinPrivate {
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

fn gen_prime(byte_length: usize, persistence: usize) -> UBig {
    loop {
        let p = gen_sized_prime(byte_length, persistence);
        if &p % 4 == 3 {
            break p;
        }
    }
}

impl RabinKeyPair {
    /// Creates a new Rabin key pair with a default persistence level of 10.
    #[inline]
    pub fn new(bit_length: usize) -> Self {
        Self::generate(bit_length, 10)
    }
}

impl PrivateKey for RabinKeyPair {
    #[inline]
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.private.sign(message)
    }

    #[inline]
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.private.decrypt(message)
    }
}

impl PublicKey for RabinKeyPair {
    #[inline]
    fn verify(&self, expected: &[u8], signed_data: &[u8]) -> Result<bool> {
        self.public.verify(expected, signed_data)
    }

    #[inline]
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        self.public.encrypt(bytes)
    }
}
