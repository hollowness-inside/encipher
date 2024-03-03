use ibig::UBig;

#[derive(Debug)]
pub struct ElGamalPrivate {
    pub prime: UBig,
    pub key: UBig,
}
