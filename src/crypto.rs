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
    secretbox::seal(plaintext, &secretbox::gen_nonce(), &secretbox::Key(key))
}