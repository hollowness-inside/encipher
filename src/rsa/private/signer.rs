use ibig::UBig;
use ibig_ext::powmod::PowMod;

use crate::result::Result;
use crate::signatures::Signer;

use super::RsaPrivate;

impl Signer for RsaPrivate {
    fn sign(&self, data: &[u8], hashf: fn(&[u8]) -> Vec<u8>) -> Result<Vec<u8>> {
        let divisor = &self.prime_1 * &self.prime_2;
        let data_hash = UBig::from_le_bytes(&hashf(data));

        let message = data_hash.powmod(self.exponent.clone(), &divisor);
        Ok(message.to_le_bytes())
    }
}
