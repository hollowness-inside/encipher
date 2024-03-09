use ibig::ubig;
use ibig_ext::{powmod::PowMod, prime_gen::gen_sized_prime};
use rand::Rng;

use super::{ElGamalPrivate, ElGamalPublic};
use crate::{keypair::KeyPair,
            message::{Content, Message},
            result::{Error, Result},
            typed::TypedContent,
            utils::{pad_message, unpad_message}};

/// A key pair for the ElGamal cryptosystem.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElGamalKeyPair {
    /// The public key for encryption.
    pub public: ElGamalPublic,

    /// The private key for decryption.
    pub private: ElGamalPrivate,

    /// The chunk size used for message padding and encryption.
    pub chunk_size: usize,
}

impl KeyPair for ElGamalKeyPair {
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
            chunk_size: 16,
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
        let blocks: Vec<_> = pad_message(&bytes, self.chunk_size)
            .chunks_exact(self.chunk_size)
            .map(|chunk| self.public.encrypt(chunk))
            .collect::<Result<_>>()?;

        Ok(Message {
            content_type,
            content: Content::ElGamal(self.chunk_size, blocks),
        })
    }

    /// Decrypts the provided message using the private key of this key pair.
    ///
    /// * `message`: The message to be decrypted, represented as a `Message` struct.
    ///
    /// Returns a `Result` containing either:
    /// * The decrypted content as a byte vector (`Vec<u8>`) on success.
    /// * An `Error` indicating the reason for failure (e.g., incorrect algorithm, decryption error).
    fn decrypt(&self, message: Message) -> Result<Vec<u8>> {
        let Content::ElGamal(chunk_size, chunks) = message.content else {
            return Err(Error::IncorrectAlgorithm);
        };

        let bytes: Vec<u8> = chunks
            .iter()
            .flat_map(|chunk| self.private.decrypt(chunk).to_le_bytes())
            .collect();

        Ok(unpad_message(&bytes, chunk_size).to_vec())
    }
}

impl ElGamalKeyPair {
    /// Creates a new ElGamal key pair with a default bit length and persistence level.
    pub fn new(bit_length: usize) -> Self {
        Self::generate(bit_length, 10)
    }

    /// Sets the chunk size used for message padding.
    pub fn set_chunk_size(&mut self, chunk_size: usize) {
        self.chunk_size = chunk_size;
    }
}
