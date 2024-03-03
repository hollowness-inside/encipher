use ibig::ubig;
use powmod::PowMod;
use prime_gen::gen_sized_prime;
use rand::Rng;

use crate::message::Content;
use crate::message::Message;
use crate::result::Result;
use crate::typed::TypedContent;
use crate::utils::pad_message;

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

    pub fn encrypt<'c, C: TypedContent>(&self, content: C) -> Result<Message> {
        let (content_type, bytes) = content.typed();
        let blocks: Vec<_> = pad_message(&bytes, self.chunk_size)
            .chunks_exact(self.chunk_size)
            .map(|chunk| self.public.encrypt(chunk))
            .collect::<Result<_>>()?;

        Ok(Message {
            content_type,
            content: Content::ElGamal(self.chunk_size, blocks),
        })
    }
}
