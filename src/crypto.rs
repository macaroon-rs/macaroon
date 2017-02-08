use error::MacaroonError;
use sodiumoxide::crypto::auth::hmacsha256::{self, Tag, Key};
use sodiumoxide::crypto::secretbox;

const KEY_GENERATOR: &'static [u8; 32] = b"macaroons-key-generator\0\0\0\0\0\0\0\0\0";

pub fn generate_derived_key(key: &[u8]) -> [u8; 32] {
    hmac(&KEY_GENERATOR, key)
}

pub fn hmac<'r>(key: &'r [u8; 32], text: &'r [u8]) -> [u8; 32] {
    let Tag(result_bytes) = hmacsha256::authenticate(text, &Key(*key));
    result_bytes
}

pub fn hmac2<'r>(key: &'r [u8; 32], text1: &'r [u8], text2: &'r [u8]) -> [u8; 32] {
    let tmp1: [u8; 32] = hmac(key, text1);
    let tmp2: [u8; 32] = hmac(key, text2);
    let tmp = [tmp1, tmp2].concat();
    hmac(key, &tmp)
}

pub fn encrypt(plaintext: &[u8], key: [u8; 32]) -> Vec<u8> {
    let nonce = secretbox::gen_nonce();
    let encrypted = secretbox::seal(plaintext, &nonce, &secretbox::Key(key));
    let mut ret: Vec<u8> = Vec::new();
    ret.extend_from_slice(nonce.as_ref());
    ret.extend(encrypted);
    ret
}

pub fn decrypt(data: &[u8], key: [u8; 32]) -> Result<Vec<u8>, MacaroonError> {
    if data.len() <= secretbox::NONCEBYTES {
        return Err(MacaroonError::DecryptionError("Encrypted data too short"));
    }
    let mut nonce: [u8; secretbox::NONCEBYTES] = [0; secretbox::NONCEBYTES];
    nonce.clone_from_slice(&data[..secretbox::NONCEBYTES]);
    let mut temp: Vec<u8> = Vec::new();
    temp.extend_from_slice(&data[secretbox::NONCEBYTES..]);
    let ciphertext = temp.as_slice();
    match secretbox::open(&ciphertext, &secretbox::Nonce(nonce), &secretbox::Key(key)) {
        Ok(plaintext) => Ok(plaintext),
        Err(_) => Err(MacaroonError::DecryptionError("Unknown decryption error")),
    }
}