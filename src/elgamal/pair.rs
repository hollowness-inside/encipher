use ibig::ubig;
use ibig_ext::{powmod::PowMod, prime_gen::gen_sized_prime};
use rand::Rng;

use super::{ElGamalPrivate, ElGamalPublic};
use crate::{result::Result, PrivateKey, PublicKey};

/// A key pair for the ElGamal cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElGamalKeyPair {
    /// The public key for encryption.
    pub public: ElGamalPublic,

    /// The private key for decryption.
    pub private: ElGamalPrivate,
}

impl ElGamalKeyPair {
    /// Generates a new ElGamal key pair with the specified bit length and persistence level.
    ///
    /// * `bit_length`: The desired bit length for the keys in the pair.
    /// * `persistence`: The number of iterations for checking numbers for primality.
    ///
    /// Returns a newly generated `ElGamalKeyPair` instance.
    pub fn new(bit_length: usize, persistence: usize) -> Self {
        let mut rng = rand::thread_rng();

        let prime = gen_sized_prime(bit_length, persistence);
        let alpha = loop {
            let i = rng.gen_range(ubig!(3)..&prime - 1);
            if i.powmod(&prime - 1, &prime) == ubig!(1) {
                break i;
            }
        };

        let key = rng.gen_range(ubig!(1)..&prime - 1);
        let beta = alpha.powmod(key.clone(), &prime);

        Self {
            public: ElGamalPublic {
                prime: prime.clone(),
                alpha,
                beta,
            },

            private: ElGamalPrivate { prime, key },
        }
    }
}

impl PrivateKey for ElGamalKeyPair {
    #[inline]
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.private.decrypt(message)
    }
}

impl PublicKey for ElGamalKeyPair {
    #[inline]
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        self.public.encrypt(bytes)
    }
}
