use super::private::RabinPrivate;
use super::public::RabinPublic;

#[derive(Debug)]
pub struct RabinKeyPair {
    pub public: RabinPublic,
    pub private: RabinPrivate,
    pub version: usize,
}
