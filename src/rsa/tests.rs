use super::RsaKeyPair;
use crate::keypair::{PrivateKey, PublicKey};

#[cfg(feature = "signatures")]
use crate::signatures::{Signer, Verifier};

const MESSAGE: [u8; 445] = *b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

#[test]
fn test_encrypt_decrypt() {
    let key = RsaKeyPair::new(128, 5);

    let encrypted = key.encrypt_chunked(&MESSAGE, 8).unwrap();
    let decrypted = key.decrypt_chunked(&encrypted, 8).unwrap();
    assert_eq!(MESSAGE, decrypted.as_slice());
}

#[cfg(feature = "signatures")]
#[test]
fn test_sign_verify() {
    fn hashf(b: &[u8]) -> Vec<u8> {
        b.iter()
            .map(|x| *x as u64)
            .sum::<u64>()
            .to_le_bytes()
            .to_vec()
    }

    let key = RsaKeyPair::new(128, 5);

    let signed = key.sign_chunked(&MESSAGE, hashf, 16).unwrap();
    let verified = key.verify_chunked(&MESSAGE, &signed, hashf, 16).unwrap();

    assert!(verified);
}
