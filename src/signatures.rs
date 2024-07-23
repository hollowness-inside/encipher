use crate::result::Result;
use crate::utils::{marshal_bytes, unmarshal_bytes};

pub trait Signer {
    fn sign(&self, data: &[u8], hashf: fn(&[u8]) -> Vec<u8>) -> Result<Vec<u8>>;

    fn sign_chunked(
        &self,
        data: &[u8],
        hashf: fn(&[u8]) -> Vec<u8>,
        chunk_size: usize,
    ) -> Result<Vec<u8>> {
        Ok(marshal_bytes(
            &data
                .chunks(chunk_size)
                .map(|chunk| self.sign(chunk, hashf))
                .collect::<Result<_>>()?,
        ))
    }
}

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
