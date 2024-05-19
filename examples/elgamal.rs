use encipher::{elgamal::ElGamalKeyPair, keypair::KeyPair};

fn main() {
    let key = ElGamalKeyPair::generate(128, 10);
    println!("{key:#?}\n");

    let encrypted = key.encrypt("Hello World", 16).unwrap();
    println!("{encrypted:#?}\n");

    let decrypted = key.decrypt(encrypted, 16).unwrap();
    println!("{:#?}\n", String::from_utf8_lossy(&decrypted));
}
