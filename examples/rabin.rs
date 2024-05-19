use encipher::{keypair::KeyPair, rabin::RabinKeyPair};

fn main() {
    let key = RabinKeyPair::generate(128, 10);
    println!("{key:#?}\n");

    let encrypted = key.encrypt("Hello World", 16).unwrap();
    println!("{encrypted:?}\n");

    let decrypted = key.decrypt(&encrypted, 16).unwrap();
    println!("{:#?}\n", String::from_utf8_lossy(&decrypted));
}
