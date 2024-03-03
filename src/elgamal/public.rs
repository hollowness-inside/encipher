use ibig::UBig;

#[derive(Debug)]
pub struct ElGamalPublic {
    pub prime: UBig,
    pub alpha: UBig,
    pub beta: UBig,
}