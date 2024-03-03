use ibig::UBig;

use super::private::RabinPrivate;
use super::public::RabinPublic;

#[derive(Debug)]
pub struct RabinKeyPair {
    pub public: RabinPublic,
    pub private: RabinPrivate,
    pub version: usize,
}

impl RabinKeyPair {
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
            version: 0,
        }
    }
}

fn gen_prime(byte_length: usize, persistence: usize) -> UBig {
    loop {
        let p = prime_gen::gen_sized_prime(byte_length, persistence);
        if &p % 4 == 3 {
            break p;
        }
    }
}
