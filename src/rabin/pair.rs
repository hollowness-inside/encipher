use ibig::UBig;
use ibig_ext::prime_gen::gen_sized_prime;

use super::{private::RabinPrivate, public::RabinPublic, MAGIC};
use crate::{keypair::{KeyPair, PrivateKey, PublicKey},
            message::{Content, Message},
            result::{Error, Result},
            typed::TypedContent};

/// A key pair for the Rabin cryptosystem.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RabinKeyPair {
    /// The public key for encryption.
    public: RabinPublic,

    /// The private key for decryption.
    private: RabinPrivate,
}

impl PublicKey for RabinPublic {}
impl PrivateKey for RabinPrivate {}

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

    /// Encrypts the provided content using the public key of this key pair.
    ///
    /// * `content`: The content to be encrypted, implementing the `TypedContent` trait.
    ///
    /// Returns a `Result` containing either:
    /// * The encrypted message (`Message`) on success.
    /// * An `Error` indicating the reason for failure.
    fn encrypt<'c, C: TypedContent>(&self, content: C) -> Result<Message> {
        let (content_type, bytes) = content.typed();
        let rabin = self.public.encrypt(&bytes)?;

        Ok(Message {
            content_type,
            content: Content::Rabin(rabin),
        })
    }

    /// Decrypts the provided message using the private key of this key pair.
    ///
    /// * `message`: The message to be decrypted, represented as a `Message` struct.
    ///
    /// Returns a `Result` containing either:
    /// * The decrypted content as a byte vector (`Vec<u8>`) on success.
    /// * An `Error::IncorrectAlgorithm` if the message content type is not `Content::Rabin`.
    /// * An `Error::MessageNotFound` if no valid decryption candidate was found.
    fn decrypt(&self, message: Message) -> Result<Vec<u8>> {
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
                    let bytes: Vec<_> = bytes[..bytes.len() - MAGIC.len()].to_vec();
                    return Some(bytes);
                }

                None
            });

        decrypted.ok_or(Error::MessageNotFound)
    }

    fn public(&self) -> &Self::Public {
        &self.public
    }

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
    pub fn new(bit_length: usize) -> Self {
        Self::generate(bit_length, 10)
    }
}
