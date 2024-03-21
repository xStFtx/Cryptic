use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use argon2::{
    password_hash::SaltString,
    Argon2, PasswordHasher, Params, Version, Algorithm,
};
use generic_array::{GenericArray, typenum::U32};
use rand::Rng;

const SALT: &[u8] = b"salasasdfasft";
const OPSLIMIT: u32 = 3;
const MEMLIMIT: u32 = 102400;

fn derive_key(password: &[u8]) -> GenericArray<u8, U32> {
    let mut rng = rand::thread_rng();
    let salt = SaltString::generate(&mut rng);
    let params = Params::new(
        OPSLIMIT,
        MEMLIMIT,
        OPSLIMIT,
        None,
    )
    .map_err(|e| e.to_string())
    .unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let hash = argon2
        .hash_password(password, &salt)
        .map(|hash| hash.hash.unwrap().as_bytes().to_vec())
        .unwrap();

    *GenericArray::from_slice(&hash[..32])
}

fn encrypt(data: &[u8], password: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let key = derive_key(password);
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(b"unique_nonce_for_this_encryption");
    cipher.encrypt(nonce, data)
}

fn decrypt(ciphertext: &[u8], password: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let key = derive_key(password);
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(b"unique_nonce_for_this_encryption");
    cipher.decrypt(nonce, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let password = b"your-secure-password";
        let plaintext = b"Hello, World!";
        let ciphertext = encrypt(plaintext, password).unwrap();
        let decrypted = decrypt(&ciphertext, password).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}