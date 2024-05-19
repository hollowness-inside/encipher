use super::RsaKeyPair;
use crate::keypair::{CryptoKey, KeyPair};

const MESSAGE: [u8; 445] = *b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

#[test]
fn test_public_encrypt_private_decrypt() {
    let key = RsaKeyPair::generate(128, 5);
    let public = key.public();
    let private = key.private();

    let encrypted = public.encrypt_chunked(&MESSAGE, 8).unwrap();
    let decrypted = private.decrypt_chunked(&encrypted, 8).unwrap();

    assert_eq!(MESSAGE, decrypted.as_slice());
}
