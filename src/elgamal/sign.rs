use crate::{Signer, Verifier};

impl Verifier for ElGamalKeyPair {
    fn verify(
        &self,
        expected: &[u8],
        signed_data: &[u8],
        hashf: fn(&[u8]) -> Vec<u8>,
    ) -> Result<bool> {
        self.public.verify(expected, signed_data, hashf)
    }
}

impl Signer for ElGamalKeyPair {
    fn sign(&self, data: &[u8], hashf: fn(&[u8]) -> Vec<u8>) -> Result<Vec<u8>> {
        self.private.sign(data, hashf)
    }
}
