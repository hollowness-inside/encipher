use ibig::{ubig, UBig};
use ibig_ext::prime_gen::gen_sized_prime;

use super::{RsaPrivate, RsaPublic};
use crate::{keypair::{KeyPair, PrivateKey, PublicKey},
            message::{Content, Message},
            result::{Error, Result},
            typed::TypedContent,
            utils::{marshal_bytes, pad_message, unmarshal_bytes, unpad_message}};

/// An RSA key pair for encryption and decryption.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RsaKeyPair {
    /// The public key for encryption.
    public: RsaPublic,

    /// The private  key for decryption.
    private: RsaPrivate,

    /// The chunk size of data for encryption/decryption (in bytes).
    pub chunk_size: usize,
}

impl KeyPair for RsaKeyPair {
    type Public = RsaPublic;
    type Private = RsaPrivate;
    /// Generates a new RSA key pair with the specified bit length and persistence level.
    ///
    /// * `bit_length`: The desired bit length for the keys in the pair.
    /// * `persistence`: The number of iterations for checking numbers for primality.
    ///
    /// Returns the newly generated `RsaKeyPair` instance.
    fn generate(bit_length: usize, persistence: usize) -> Self {
        let p = gen_sized_prime(bit_length, persistence);
        let q = gen_sized_prime(bit_length, persistence);

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
                exponent: d,
                prime_1: p,
                prime_2: q,
            },
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
    /// * `Error::SmallKey` if the message is too large for the key.
    /// * Other potential errors during encryption or padding.
    ///
    fn encrypt<C: TypedContent>(&self, message: C) -> Result<Message> {
        let (content_type, bytes) = message.typed();

        let content: Vec<Vec<_>> = pad_message(&bytes, self.chunk_size)
            .chunks(self.chunk_size - 1)
            .map(|chunk| self.public.encrypt(chunk))
            .collect::<Result<_>>()?;

        let content = marshal_bytes(&content);
        let content = Content::Rsa(self.chunk_size, content);

        Ok(Message {
            content_type,
            content,
        })
    }

    /// Decrypts the provided message using the private key of this key pair.
    ///
    /// * `message`: The message to be decrypted, represented as a `Message` struct.
    ///
    /// Returns a `Result` containing either:
    /// * The decrypted content as a byte vector (`Vec<u8>`) on success.
    /// * An `Error` indicating the reason for failure:
    /// * `Error::IncorrectAlgorithm` if the message content type is not `Content::Rsa`.
    /// * Other potential errors during decryption or unpadding.
    fn decrypt(&self, message: Message) -> Result<Vec<u8>> {
        let Content::Rsa(chunk_size, raw_bytes) = message.content else {
            return Err(Error::IncorrectAlgorithm);
        };

        let chunks = unmarshal_bytes(&raw_bytes);
        let bytes: Vec<u8> = chunks
            .into_iter()
            .map(|chunk| self.private.decrypt(&chunk))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();

        Ok(unpad_message(&bytes, chunk_size).to_vec())
    }

    fn public(&self) -> &Self::Public {
        &self.public
    }

    fn private(&self) -> &Self::Private {
        &self.private
    }
}

impl RsaKeyPair {
    /// Creates a new RSA key pair with a default persistence level of 10.
    pub fn new(bit_length: usize) -> Self {
        Self::generate(bit_length, 10)
    }

    /// Sets the chunk size used for message padding.
    pub fn set_chunk_size(&mut self, chunk_size: usize) {
        self.chunk_size = chunk_size;
    }
}
