use rand::{Rng, thread_rng};
use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use sha2::{Sha256, Digest};
use aes::cipher::{KeyInit , BlockDecrypt , BlockEncrypt};
/// Generates a random AES key.
pub fn generate_aes_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    thread_rng().fill(&mut key);
    key
}

/// Encrypts data using AES256.
pub fn aes_encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut buffer = data.to_vec();
    let len = buffer.len();
    let padding_len = 16 - (len % 16);
    buffer.extend(vec![padding_len as u8; padding_len]);
    for chunk in buffer.chunks_mut(16) {
        cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
    }
    buffer
}

/// Decrypts data using AES256.
pub fn aes_decrypt(data: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    if data.len() % 16 != 0 {
        return None; // Input data length is not a multiple of block size
    }
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut buffer = data.to_vec();
    for chunk in buffer.chunks_mut(16) {
        cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
    }
    let padding_len = buffer.last()?;
    buffer.truncate(buffer.len() - *padding_len as usize);
    Some(buffer)
}

/// Computes SHA256 hash.
pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

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