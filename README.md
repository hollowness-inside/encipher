# encipher
Library that implements RSA, Rabin, and ElGamal encryption systems for encrypting and decrypting data.
Rabin does not currently work.

# Usage
```rust
use encipher::{PrivateKey, PublicKey};

fn main() {
    let message = b"Hello World";

    // let key = encipher::elgamal::ElGamalKeyPair::new(128, 10);
    // let key = encipher::rabin::RabinKeyPair::new(128, 10);
    let key = encipher::rsa::RsaKeyPair::new(128, 10);

    let encrypted = key.encrypt_chunked(message, 16).unwrap();
    let decrypted = key.decrypt_chunked(&encrypted, 16).unwrap();

    println!("{encrypted:?}\n");
    println!("{:#?}\n", String::from_utf8_lossy(&decrypted));
}
```
