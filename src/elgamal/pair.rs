use super::private::ElGamalPrivate;
use super::public::ElGamalPublic;

#[derive(Debug)]
pub struct ElGamalKeyPair {
    pub public: ElGamalPublic,
    pub private: ElGamalPrivate,
    pub chunk_size: usize,
}