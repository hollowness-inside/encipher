use crate::{
    result::Result,
    utils::{marshal_bytes, unmarshal_bytes},
};

/// Trait defining the common functionalities of a public-private cryptography key pair.
pub trait KeyPair: PublicKey + PrivateKey + Signer + Verifier {}

pub trait PublicKey {
    /// Encrypts a byte slice using the public key.
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>>;

    fn encrypt_chunked(&self, bytes: &[u8], chunk_size: usize) -> Result<Vec<u8>> {
        let content: Vec<Vec<_>> = bytes
            .chunks(chunk_size)
            .flat_map(|chunk| self.encrypt(chunk))
            .collect();

        Ok(marshal_bytes(&content))
    }
}

pub trait PrivateKey {
    /// Decrypts an encrypted slice using the public key.
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>>;

    /// Unmarshalls the given slice containing chunks and then decrypts each separately using the public key.
    fn decrypt_chunked(&self, message: &[u8], _chunk_size: usize) -> Result<Vec<u8>> {
        let bytes: Vec<u8> = unmarshal_bytes(message)
            .iter()
            .flat_map(|chunk| self.decrypt(chunk))
            .flatten()
            .collect();

        Ok(bytes)
    }
}

pub trait Signer {}

pub trait Verifier {
    fn verify(
        &self,
        expected: &[u8],
        signed_data: &[u8],
        hashf: fn(&[u8]) -> Vec<u8>,
    ) -> Result<bool>;

    fn verify_chunked(
        &self,
        expected: &[u8],
        signed_data: &[u8],
        hashf: fn(&[u8]) -> Vec<u8>,
        chunk_size: usize,
    ) -> Result<bool> {
        Ok(unmarshal_bytes(signed_data)
            .iter()
            .zip(expected.chunks(chunk_size))
            .flat_map(|(sig, exp)| self.verify(exp, sig, hashf))
            .all(|b| b))
    }
}
