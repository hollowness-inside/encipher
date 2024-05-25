use encipher::{keypair::{KeyPair, PrivateKey, PublicKey},
               rsa::RsaKeyPair};

fn main() {
    let message = b"Hello World";

    let key = RsaKeyPair::generate(128, 10);
    println!("{key:#?}\n");

    // Using key directly
    let encrypted = key.encrypt_chunked(message, 16).unwrap();
    let decrypted = key.decrypt_chunked(&encrypted, 16).unwrap();
    println!("{encrypted:?}\n");
    println!("{:#?}\n", String::from_utf8_lossy(&decrypted));

    // Using public and private keys explicitly
    let encrypted = key.public().encrypt_chunked(message, 16).unwrap();
    let decrypted = key.private().decrypt_chunked(&encrypted, 16).unwrap();
    println!("{:#?}\n", String::from_utf8_lossy(&decrypted));

    // Sign data
    let signed = key.sign_chunked(message, 8).unwrap();
    let verification = key.verify_chunked(message, &signed, 8).unwrap();
    println!("{verification}");
}
