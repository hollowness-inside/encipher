use ibig::UBig;

use crate::message::{Content, Message};
use crate::result::{Error, Result};
use crate::typed::TypedContent;

use super::private::RabinPrivate;
use super::public::RabinPublic;
use super::MAGIC;

#[derive(Debug)]
pub struct RabinKeyPair {
    pub public: RabinPublic,
    pub private: RabinPrivate,
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
        }
    }

    pub fn encrypt<'c, C: TypedContent>(&self, content: C) -> Result<Message> {
        let (content_type, bytes) = content.typed();
        let rabin = self.public.encrypt(&bytes)?;

        Ok(Message {
            content_type,
            content: Content::Rabin(rabin),
        })
    }

    pub fn decrypt(&self, message: Message) -> Result<Vec<u8>> {
        let Content::Rabin(content) = message.content else {
            return Err(Error::IncorrectAlgorithm);
        };

        let decrypted: Option<Vec<u8>> =
            self.private.decrypt(content).into_iter().find_map(|msg| {
                let Ok(msg) = TryInto::<UBig>::try_into(msg) else {
                    return None;
                };

                let bytes = msg.to_le_bytes();
                if bytes.ends_with(MAGIC) {
                    let bytes: Vec<_> = bytes[..bytes.len() - 8].to_vec();
                    return Some(bytes);
                }

                None
            });

        decrypted.ok_or(Error::MessageNotFound)
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
