use encipher::elgamal::ElGamalKeyPair;

fn main() {
    let key = ElGamalKeyPair::new(128, 10);
    println!("{key:#?}\n");

    let out = key.encrypt("Hello World").unwrap();
    println!("{out:#?}\n");

    let decrypted = key.decrypt(out).unwrap();
    println!("{:#?}\n", String::from_utf8_lossy(&decrypted));
}
