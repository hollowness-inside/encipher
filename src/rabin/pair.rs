use ibig::UBig;
use ibig_ext::prime_gen::gen_sized_prime;

use super::{private::RabinPrivate, public::RabinPublic};
use crate::{result::Result, PrivateKey, PublicKey};

/// A key pair for the Rabin cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RabinKeyPair {
    /// The public key for encryption.
    pub public: RabinPublic,

    /// The private key for decryption.
    pub private: RabinPrivate,
}

impl RabinKeyPair {
    /// Generates a new Rabin key pair with the specified bit length and persistence level.
    ///
    /// * `bit_length`: The desired bit length for the keys in the pair (increased by 8 for internal logic).
    /// * `persistence`: The number of iterations for checking numbers for primality.
    ///
    /// Returns a newly generated `RabinKeyPair` instance.
    #[inline]
    pub fn new(mut bit_length: usize, persistence: usize) -> Self {
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
}

impl PrivateKey for RabinKeyPair {
    #[inline]
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.private.decrypt(message)
    }
}

impl PublicKey for RabinKeyPair {
    #[inline]
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        self.public.encrypt(bytes)
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
