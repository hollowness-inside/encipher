use encipher::{elgamal::ElGamalKeyPair, PrivateKey, PublicKey};

fn main() {
    let message = b"Hello World";

    let key = ElGamalKeyPair::new(128, 10);
    println!("{key:#?}\n");

    let encrypted = key.encrypt_chunked(message, 16).unwrap();
    let decrypted = key.decrypt_chunked(&encrypted, 16).unwrap();
    println!("{encrypted:?}\n");
    println!("{:#?}\n", String::from_utf8_lossy(&decrypted));
}
