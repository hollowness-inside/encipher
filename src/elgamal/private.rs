use ibig::UBig;
use powmod::PowMod;

#[derive(Debug)]
pub struct ElGamalPrivate {
    pub prime: UBig,
    pub key: UBig,
}

impl ElGamalPrivate {
    pub fn decrypt(&self, message: &[UBig; 2]) -> UBig {
        let [c1, c2] = message;

        let (_, c1_inv, _) = c1.extended_gcd(&self.prime);
        let c1_inv: UBig = c1_inv.try_into().expect("c1 inverse is negative");
        (c2 * c1_inv.powmod(self.key.clone(), &self.prime)) % &self.prime
    }
}
