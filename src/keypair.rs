use crate::{
    result::Result,
    utils::{marshal_bytes, unmarshal_bytes},
};

/// Trait defining the common functionalities of a public-private cryptography key pair.
pub trait KeyPair: PublicKey + PrivateKey {}

pub trait PrivateKey {
    /// Decrypts an encrypted slice using the public key.
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>>;

    /// Unmarshalls the given slice containing chunks and then decrypts each separately using the public key.
    fn decrypt_chunked(&self, message: &[u8], _chunk_size: usize) -> Result<Vec<u8>> {
        let bytes: Vec<u8> = unmarshal_bytes(message)
            .iter()
            .map(|chunk| {
                self.decrypt(chunk).map(|mut v| {
                    v.pop();
                    v
                })
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();

        Ok(bytes)
    }
}

pub trait PublicKey {
    /// Encrypts a byte slice using the public key.
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>>;

    fn encrypt_chunked(&self, bytes: &[u8], chunk_size: usize) -> Result<Vec<u8>> {
        let content: Vec<Vec<_>> = bytes
            .chunks(chunk_size - 1)
            .map(|chunk| {
                let mut chunk = chunk.to_vec();
                chunk.push(0x01);
                self.encrypt(&chunk)
            })
            .collect::<Result<_>>()?;

        Ok(marshal_bytes(&content))
    }
}
