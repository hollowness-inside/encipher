# encipher
Library that implements RSA, Rabin, and ElGamal encryption systems for encrypting and decrypting data, and also signing and verifying digital signatures.
The algorithms are customly implemented and do not conform to any standards.

Rabin does not currently work.

# Usage
## Encryption
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

## Digital Signatures
```rust
fn main() {
    // Use a better hash function than this
    fn hashf(b: &[u8]) -> Vec<u8> {
        b.iter()
            .map(|x| *x as u64)
            .sum::<u64>()
            .to_le_bytes()
            .to_vec()
    }

    // let key = encipher::ElGamalKeyPair::new(128, 5);
    let key = encipher::RsaKeyPair::new(128, 5);

    let signed = key.sign_chunked(b"Hello World", hashf, 16).unwrap();
    let verified = key.verify_chunked(b"Hello World", &signed, hashf, 16).unwrap();

    assert!(verified);
}

```
