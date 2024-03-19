# Crypticy

This Rust crate provides functionalities for AES encryption using AES256 and SHA256 hashing.

## Usage

Add this crate to your `Cargo.toml` file:

```toml
[dependencies]
crypticy = "0.1.0"
```

Then, you can use the crate in your Rust code as follows:

```rust
extern crate aes_encryption;

use aes_encryption::{generate_aes_key, aes_encrypt, aes_decrypt, sha256_hash};

fn main() {
    // Generate a random AES key
    let key = generate_aes_key();

    // Encrypt data using AES256
    let plaintext = b"Your data here";
    let ciphertext = aes_encrypt(plaintext, &key);

    // Decrypt data using AES256
    let decrypted = aes_decrypt(&ciphertext, &key).unwrap();

    // Compute SHA256 hash
    let data = b"Your data here";
    let hash = sha256_hash(data);
}
```

## License

This crate is licensed under the MIT License.

