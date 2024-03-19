// Import necessary crates
extern crate rand;
extern crate aes;
extern crate sha2;
extern crate digest;

use rand::{Rng, thread_rng};
use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, BlockDecrypt,KeyInit}; // Import BlockEncrypt and BlockDecrypt
use sha2::{Sha256, Digest};

// Function to generate a random key
pub fn generate_aes_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    thread_rng().fill(&mut key);
    key
}

// Function to encrypt data using AES256
pub fn aes_encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(key)); // Use new directly
    let mut buffer = data.to_vec();
    let len = buffer.len();
    // Pad the input to be a multiple of block size
    let padding_len = 16 - (len % 16);
    buffer.extend(vec![padding_len as u8; padding_len]);
    // Encrypt the padded data
    for chunk in buffer.chunks_mut(16) {
        cipher.encrypt_block(GenericArray::from_mut_slice(chunk)); // Use encrypt_block
    }
    buffer
}

// Function to decrypt data using AES256
pub fn aes_decrypt(data: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    if data.len() % 16 != 0 {
        return None; // Input data length is not a multiple of block size
    }
    let cipher = Aes256::new(GenericArray::from_slice(key)); // Use new directly
    let mut buffer = data.to_vec();
    // Decrypt the data
    for chunk in buffer.chunks_mut(16) {
        cipher.decrypt_block(GenericArray::from_mut_slice(chunk)); // Use decrypt_block
    }
    // Remove padding
    let padding_len = buffer.last()?;
    buffer.truncate(buffer.len() - *padding_len as usize);
    Some(buffer)
}

// Function to compute SHA256 hash
pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_encrypt_decrypt() {
        let key = generate_aes_key();
        let plaintext = b"Hello, World!";
        let ciphertext = aes_encrypt(plaintext, &key);
        let decrypted = aes_decrypt(&ciphertext, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_sha256_hash() {
        let data = b"Hello, World!";
        let hash = sha256_hash(data);
        assert_eq!(hash.len(), 32);
    }
}