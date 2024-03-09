use encipher::{keypair::KeyPair, rsa::RsaKeyPair};

fn main() {
    let key = RsaKeyPair::generate(128, 10);
    println!("{key:#?}\n");

    let encrypted = key.encrypt("Hello World").unwrap();
    let json = serde_json::to_string_pretty(&encrypted).unwrap();
    println!("{}\n", json);

    let decrypted = key.decrypt(encrypted).unwrap();
    println!("{:#?}\n", String::from_utf8_lossy(&decrypted));
}
