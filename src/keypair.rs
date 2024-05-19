use crate::{result::Result,
            typed::{Content, ToBytes},
            utils::{unmarshal_bytes, unpad_message}};

pub trait PublicKey {
    /// Encrypts a byte slice using the public key.
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>>;
    /// Encrypts a byte slice chunk by chunk using the public key and returns a marshalled vector.
    fn encrypt_chunked(&self, bytes: &[u8], chunk_size: usize) -> Result<Vec<u8>>;

    /// Decrypts an encrypted slice using the public key.
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>>;
    /// Unmarshalls the given slice containing chunks and then decrypts each separately using the public key.
    fn decrypt_chunked(&self, message: &[u8], chunk_size: usize) -> Result<Vec<u8>>;
}
pub trait PrivateKey {
    /// Decrypts an encrypted slice using the public key.
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>>;
    /// Unmarshalls the given slice containing chunks and then decrypts each separately using the public key.
    fn decrypt_chunked(&self, message: &[u8], chunk_size: usize) -> Result<Vec<u8>>;

    /// Encrypts a byte slice using the public key.
    fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>>;
    /// Encrypts a byte slice chunk by chunk using the public key and returns a marshalled vector.
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
    fn encrypt<C: ToBytes>(&self, message: C, chunk_size: usize) -> Result<Content> {
        let bytes = message.to_bytes();
        let encrypted = self.public().encrypt_chunked(&bytes, chunk_size)?;
        Ok(Content::new(chunk_size, &encrypted))
    }

    /// Decrypts the provided message using the private key of this key pair.
    fn decrypt(&self, message: &[u8], chunk_size: usize) -> Result<Vec<u8>> {
        let chunks = unmarshal_bytes(message);
        let bytes: Vec<u8> = chunks
            .into_iter()
            .map(|chunk| self.private().decrypt(&chunk))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();

        Ok(unpad_message(&bytes, chunk_size).to_vec())
    }

    fn public(&self) -> &Self::Public;
    fn private(&self) -> &Self::Private;
}
