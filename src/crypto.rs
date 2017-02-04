use error::MacaroonError;
use sodiumoxide::crypto::auth::hmacsha256::{self, Tag, Key};
use sodiumoxide::crypto::secretbox;

const KEY_GENERATOR: &'static [u8; 32] = b"macaroons-key-generator\0\0\0\0\0\0\0\0\0";

pub fn generate_derived_key(key: &[u8; 32]) -> Result<[u8; 32], MacaroonError> {
    hmac_vec(&KEY_GENERATOR.to_vec(), key)
}

pub fn hmac_vec<'r>(key: &'r Vec<u8>, text: &'r [u8]) -> Result<[u8; 32], MacaroonError> {
    if key.len() != 32 {
        return Err(MacaroonError::KeyError("Wrong key length"));
    }
    let mut key_static: [u8; 32] = [0; 32];
    for i in 0..key.len() {
        key_static[i] = key[i];
    }
    Ok(hmac(&key_static, text))
}

pub fn hmac<'r>(key: &'r [u8; 32], text: &'r [u8]) -> [u8; 32] {
    let Tag(result_bytes) = hmacsha256::authenticate(text, &Key(*key));
    result_bytes
}

pub fn hmac2<'r>(key: &'r Vec<u8>, text1: &'r [u8], text2: &'r [u8]) -> Result<[u8; 32], MacaroonError> {
    let tmp1: [u8;32] = hmac_vec(key, text1)?;
    let tmp2: [u8;32] = hmac_vec(key, text2)?;
    let tmp = [tmp1, tmp2].concat();
    hmac_vec(key, &tmp)
}

pub fn encrypt(plaintext: &[u8], key: [u8;32]) -> Vec<u8> {
    secretbox::seal(plaintext, &secretbox::gen_nonce(), &secretbox::Key(key))
}