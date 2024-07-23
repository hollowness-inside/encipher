use crate::result::Result;
use crate::signatures::{Signer, Verifier};

use super::RsaKeyPair;

impl Verifier for RsaKeyPair {
    #[inline]
    fn verify(
        &self,
        expected: &[u8],
        signed_data: &[u8],
        hashf: fn(&[u8]) -> Vec<u8>,
    ) -> Result<bool> {
        self.public.verify(expected, signed_data, hashf)
    }
}

impl Signer for RsaKeyPair {
    #[inline]
    fn sign(&self, data: &[u8], hashf: fn(&[u8]) -> Vec<u8>) -> Result<Vec<u8>> {
        self.private.sign(data, hashf)
    }
}
