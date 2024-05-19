use encipher::{keypair::KeyPair, rsa::RsaKeyPair};

fn main() {
    let key = RsaKeyPair::generate(128, 10);
    let key_json = serde_json::to_string_pretty(&key).unwrap();
    println!("{key_json}\n",);

    let encrypted = key.encrypt("Hello World", 16).unwrap();
    let e_json = serde_json::to_string_pretty(&encrypted).unwrap();
    println!("{e_json}\n");

    let decrypted = key.decrypt(&encrypted, 16).unwrap();
    println!("{:#?}\n", String::from_utf8_lossy(&decrypted));
}
