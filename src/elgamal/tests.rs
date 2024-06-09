use ibig::{ops::RemEuclid, UBig};
use ibig_ext::powmod::PowMod;

use super::basic::elgamal_encrypt;
use crate::{elgamal::{basic::elgamal_decrypt, ElGamalKeyPair},
            keypair::{KeyPair, PrivateKey, PublicKey},
            utils::unmarshal_bytes};

const MESSAGE: [u8; 445] = *b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

#[test]
fn test_encrypt_decrypt() {
    let key = ElGamalKeyPair::generate(128, 5);

    let encrypted = key.public().encrypt_chunked(&MESSAGE, 8).unwrap();
    let decrypted = key.private().decrypt_chunked(&encrypted, 8).unwrap();
    assert_eq!(MESSAGE, decrypted.as_slice());
}

// #[test]
// fn test_sign_verify() {
//     let key = ElGamalKeyPair::generate(128, 5);
//     let signed = key.sign_chunked(&MESSAGE, 8).unwrap();
//     assert!(key.verify_chunked(&MESSAGE, &signed, 8).unwrap());
// }

#[test]
fn test() {
    let key = ElGamalKeyPair::new(128);
    let encrypted = key.encrypt_chunked(MESSAGE.as_ref(), 8);
}
