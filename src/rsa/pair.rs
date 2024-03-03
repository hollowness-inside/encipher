use ibig::{ubig, UBig};

use crate::message::{Content, Message};
use crate::result::{Error, Result};
use crate::typed::TypedContent;
use crate::utils::{pad_message, unpad_message};

use super::{RsaPrivate, RsaPublic};

#[derive(Debug)]
pub struct RsaKeyPair {
    pub public: RsaPublic,
    pub private: RsaPrivate,
    pub chunk_size: usize,
}

impl RsaKeyPair {
    pub fn new(bit_length: usize, persistence: usize) -> Self {
        let p = prime_gen::gen_sized_prime(bit_length, persistence);
        let q = prime_gen::gen_sized_prime(bit_length, persistence);

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
                private_exponent: d,
                prime_1: p,
                prime_2: q,
            },
            chunk_size: 16,
        }
    }

    pub fn encrypt<C: TypedContent>(&self, message: C) -> Result<Message> {
        let (content_type, bytes) = message.typed();

        let content: Vec<_> = pad_message(&bytes, self.chunk_size)
            .chunks_exact(self.chunk_size)
            .map(|chunk| self.public.encrypt(chunk))
            .collect::<Result<_>>()?;

        let content = Content::Rsa(self.chunk_size, content);

        Ok(Message {
            content_type,
            content,
        })
    }

    pub fn decrypt(&self, message: Message) -> Result<Vec<u8>> {
        let Content::Rsa(chunk_size, chunks) = message.content else {
            return Err(Error::IncorrectAlgorithm);
        };

        let bytes: Vec<u8> = chunks
            .iter()
            .flat_map(|chunk| self.private.decrypt(chunk).to_le_bytes())
            .collect();

        Ok(unpad_message(&bytes, chunk_size).to_vec())
    }
}
