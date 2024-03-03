use ibig::ubig;
use powmod::PowMod;
use prime_gen::gen_sized_prime;
use rand::Rng;

use super::ElGamalPrivate;
use super::ElGamalPublic;

#[derive(Debug)]
pub struct ElGamalKeyPair {
    pub public: ElGamalPublic,
    pub private: ElGamalPrivate,
    pub chunk_size: usize,
}

impl ElGamalKeyPair {
    pub fn new(bit_length: usize, persistence: usize) -> Self {
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
            chunk_size: 16,
        }
    }
}
