use ibig::UBig;
use ibig_ext::powmod::PowMod;

use super::encrypter::RsaPublic;
use crate::result::Result;
use crate::signatures::Verifier;

impl Verifier for RsaPublic {
    fn verify(
        &self,
        expected: &[u8],
        signed_data: &[u8],
        hashf: fn(&[u8]) -> Vec<u8>,
    ) -> Result<bool> {
        let expected_hash = hashf(expected);

        let mut out = UBig::from_le_bytes(signed_data)
            .powmod(self.exponent.clone(), &self.divisor)
            .to_le_bytes()
            .to_vec();
        out.resize(expected_hash.len(), 0);

        Ok(out.eq(&expected_hash))
    }
}
