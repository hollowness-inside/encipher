use ibig::ubig;
use ibig_ext::{powmod::PowMod, prime_gen::gen_sized_prime};
use rand::Rng;

use super::{ElGamalPrivate, ElGamalPublic};
use crate::keypair::KeyPair;

/// A key pair for the ElGamal cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElGamalKeyPair {
    /// The public key for encryption.
    public: ElGamalPublic,

    /// The private key for decryption.
    private: ElGamalPrivate,
}

impl KeyPair for ElGamalKeyPair {
    type Public = ElGamalPublic;
    type Private = ElGamalPrivate;
    /// Generates a new ElGamal key pair with the specified bit length and persistence level.
    ///
    /// * `bit_length`: The desired bit length for the keys in the pair.
    /// * `persistence`: The number of iterations for checking numbers for primality.
    ///
    /// Returns a newly generated `ElGamalKeyPair` instance.
    fn generate(bit_length: usize, persistence: usize) -> Self {
        let mut rng = rand::thread_rng();

        let prime = gen_sized_prime(bit_length, persistence);
        let key = rng.gen_range(ubig!(1)..=&prime - 2);

        let alpha = loop {
            let i = rng.gen_range(ubig!(3)..=&prime - 2);
            if i.powmod(&prime - 1, &prime) == ubig!(1) {
                break i;
            }
        };

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

    fn public(&self) -> &Self::Public {
        &self.public
    }

    fn private(&self) -> &Self::Private {
        &self.private
    }
}

impl ElGamalKeyPair {
    /// Creates a new ElGamal key pair with a default bit length and persistence level.
    pub fn new(bit_length: usize) -> Self {
        Self::generate(bit_length, 10)
    }
}
