use encipher::{keypair::{KeyPair, PrivateKey, PublicKey},
               rsa::RsaKeyPair};

fn main() {
    let key = RsaKeyPair::generate(128, 10);
    println!("{key:#?}\n");

    // Using key directly
    let encrypted = key.encrypt_chunked(b"Hello World", 16).unwrap();
    let decrypted = key.decrypt_chunked(&encrypted, 16).unwrap();
    println!("{encrypted:?}\n");
    println!("{:#?}\n", String::from_utf8_lossy(&decrypted));

    // Using public and private keys explicitly
    let encrypted = key.public().encrypt_chunked(b"Hello World", 16).unwrap();
    let decrypted = key.private().decrypt_chunked(&encrypted, 16).unwrap();
    println!("{:#?}\n", String::from_utf8_lossy(&decrypted));
}
