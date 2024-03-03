use encipher::rabin::RabinKeyPair;

fn main() {
    let key = RabinKeyPair::new(128, 10);
    println!("{key:#?}\n");

    let encrypted = key.encrypt("Hello World").unwrap();
    println!("{encrypted:#?}\n");

    let decrypted = key.decrypt(encrypted);
    println!(
        "{:#?}\n",
        decrypted
            .iter()
            .map(|x| String::from_utf8_lossy(x))
            .collect::<Vec<_>>()
    );
}
