use ibig::{IBig, UBig};

#[derive(Debug)]
pub struct RabinPrivate {
    pub prime_1: UBig,
    pub prime_2: UBig,
}

impl RabinPrivate {
    pub fn decrypt(&self, message: UBig) -> [IBig; 4] {
        let p1: IBig = self.prime_1.clone().into();
        let p2: IBig = self.prime_2.clone().into();

        let (_, u, v) = self.prime_1.extended_gcd(&self.prime_2);

        let mp1: IBig = message
            .clone()
            .square_root_mod(&self.prime_1)
            .expect("No root")
            .0
            .into();

        let mp2: IBig = message
            .square_root_mod(&self.prime_2)
            .expect("No root")
            .0
            .into();

        let n = &p1 * &p2;
        let m1 = (&u * &p1 * &mp2 + &v * &p2 * &mp1) % &n;
        let m2 = &n - &m1;
        let m3 = (&u * &p1 * &mp2 - &v * &p2 * &mp1) % &n;
        let m4 = &n - &m3;

        [m1, m2, m3, m4]
    }
}
