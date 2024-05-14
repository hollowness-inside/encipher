use crate::{message::Message, result::Result, typed::TypedContent};

pub trait PublicKey {
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>>;
    fn encrypt_chunked(&self, bytes: &[u8], chunk_size: usize) -> Result<Vec<u8>>;

    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_marshalled(&self, message: &[u8]) -> Result<Vec<u8>>;
}
pub trait PrivateKey {
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_marshalled(&self, message: &[u8]) -> Result<Vec<u8>>;
    
    fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>>;
    fn encrypt_chunked(&self, bytes: &[u8], chunk_size: usize) -> Result<Vec<u8>>;
}

/// Trait defining the common functionalities of a public-private cryptography key pair.
pub trait KeyPair {
    type Public: PublicKey;
    type Private: PrivateKey;
    /// Generates a new key pair with the specified key bit length and persistence level.
    ///
    /// * `bit_length`: The desired bit length for the keys in the pair.
    /// * `persistence`: The persistence level of the key pair (e.g., in-memory, file storage).
    ///
    /// Returns the newly generated `Self` instance representing the key pair.
    fn generate(bit_length: usize, persistence: usize) -> Self;

    /// Encrypts the provided content using the public key of this key pair.
    ///
    /// * `content`: The content to be encrypted, implementing the `TypedContent` trait.
    ///
    /// Returns a `Result` containing either the encrypted message (`Message`) on success or an error (`Error`) indicating the reason for failure.
    fn encrypt<C: TypedContent>(&self, content: C) -> Result<Message>;

    /// Decrypts the provided message using the private key of this key pair.
    ///
    /// * `message`: The message to be decrypted, represented as a `Message` struct.
    ///
    /// Returns a `Result` containing either the decrypted content as a byte vector (`Vec<u8>`) on success or an error (`Error`) indicating the reason for failure.
    fn decrypt(&self, message: Message) -> Result<Vec<u8>>;

    fn public(&self) -> &Self::Public;
    fn private(&self) -> &Self::Private;
}
