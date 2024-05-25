use crate::{result::Result,
            utils::{marshal_bytes, pad_message, unmarshal_bytes, unpad_message}};

pub trait CryptoKey {
    /// Encrypts a byte slice using the public key.
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>>;
    /// Encrypts a byte slice chunk by chunk using the public key and returns a marshalled vector.

    #[inline]
    fn encrypt_chunked(&self, bytes: &[u8], chunk_size: usize) -> Result<Vec<u8>> {
        let content: Vec<Vec<_>> = pad_message(bytes, chunk_size)
            .chunks(chunk_size - 1)
            .map(|chunk| {
                let mut chunk = chunk.to_vec();
                chunk.push(0x01);
                self.encrypt(&chunk)
            })
            .collect::<Result<_>>()?;

        Ok(marshal_bytes(&content))
    }

    /// Decrypts an encrypted slice using the public key.
    fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>>;
    /// Unmarshalls the given slice containing chunks and then decrypts each separately using the public key.
    fn decrypt_chunked(&self, message: &[u8], chunk_size: usize) -> Result<Vec<u8>> {
        let bytes: Vec<u8> = unmarshal_bytes(message)
            .iter()
            .map(|chunk| {
                self.decrypt(chunk).and_then(|mut v| {
                    v.pop();
                    Ok(v)
                })
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();

        Ok(unpad_message(&bytes, chunk_size).to_vec())
    }
}

/// Trait defining the common functionalities of a public-private cryptography key pair.
pub trait KeyPair: CryptoKey + Signer {
    type Public: CryptoKey + Verifier;
    type Private: CryptoKey + Signer;
    /// Generates a new key pair with the specified key bit length and persistence level.
    ///
    /// * `bit_length`: The desired bit length for the keys in the pair.
    /// * `persistence`: The persistence level of the key pair (e.g., in-memory, file storage).
    ///
    /// Returns the newly generated `Self` instance representing the key pair.
    fn generate(bit_length: usize, persistence: usize) -> Self;
    fn public(&self) -> &Self::Public;
    fn private(&self) -> &Self::Private;
}

pub trait Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
    fn sign_chunked(&self, message: &[u8], chunk_size: usize) -> Result<Vec<u8>> {
        let content: Vec<Vec<_>> = pad_message(message, chunk_size)
            .chunks(chunk_size - 1)
            .map(|chunk| {
                let mut chunk = chunk.to_vec();
                chunk.push(0x01);
                self.sign(&chunk)
            })
            .collect::<Result<_>>()?;

        Ok(marshal_bytes(&content))
    }
}

pub trait Verifier {
    fn verify(&self, message: &[u8]) -> Result<bool>;
    fn verify_chunked(&self, message: &[u8]) -> Result<bool> {
        let x = unmarshal_bytes(message)
            .iter()
            .any(|chunk| match self.verify(&chunk) {
                Ok(true) => false,
                _ => true,
            });

        Ok(!x)
    }
}
