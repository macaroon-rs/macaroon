use error::MacaroonError;
use sodiumoxide::crypto::auth::hmacsha256::{self, Tag, Key};
use sodiumoxide::crypto::secretbox;

const KEY_GENERATOR: &[u8; 32] = b"macaroons-key-generator\0\0\0\0\0\0\0\0\0";

pub fn generate_derived_key(key: &[u8]) -> [u8; 32] {
    hmac(KEY_GENERATOR, key)
}

pub fn generate_signature(key: &[u8], text: &str) -> [u8; 32] {
    let mut key_bytes: [u8; 32] = [0; 32];
    key_bytes[..key.len()].clone_from_slice(key);
    hmac(&key_bytes, text.as_bytes())
}

pub fn hmac(key: &[u8; 32], text: &[u8]) -> [u8; 32] {
    let Tag(result_bytes) = hmacsha256::authenticate(text, &Key(*key));
    result_bytes
}

pub fn hmac2(key: &[u8; 32], text1: &[u8], text2: &[u8]) -> [u8; 32] {
    let tmp1: [u8; 32] = hmac(key, text1);
    let tmp2: [u8; 32] = hmac(key, text2);
    let tmp = [tmp1, tmp2].concat();
    hmac(key, &tmp)
}

pub fn encrypt(key: [u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let nonce = secretbox::gen_nonce();
    let encrypted = secretbox::seal(plaintext, &nonce, &secretbox::Key(key));
    let mut ret: Vec<u8> = Vec::new();
    ret.extend(&nonce.0);
    ret.extend(encrypted);
    ret
}

pub fn decrypt(key: [u8; 32], data: &[u8]) -> Result<Vec<u8>, MacaroonError> {
    if data.len() <= secretbox::NONCEBYTES + secretbox::MACBYTES {
        error!("crypto::decrypt: Encrypted data {:?} too short", data);
        return Err(MacaroonError::DecryptionError("Encrypted data too short"));
    }
    let mut nonce: [u8; secretbox::NONCEBYTES] = [0; secretbox::NONCEBYTES];
    nonce.clone_from_slice(&data[..secretbox::NONCEBYTES]);
    let mut temp: Vec<u8> = Vec::new();
    temp.extend(&data[secretbox::NONCEBYTES..]);
    let ciphertext = temp.as_slice();
    match secretbox::open(ciphertext, &secretbox::Nonce(nonce), &secretbox::Key(key)) {
        Ok(plaintext) => Ok(plaintext),
        Err(()) => {
            error!("crypto::decrypt: Unknown decryption error decrypting {:?}", data);
            Err(MacaroonError::DecryptionError("Unknown decryption error"))
        }
    }
}

#[cfg(test)]
mod test {
    use super::{encrypt, decrypt};

    #[test]
    fn test_encrypt_decrypt() {
        let secret = b"This is my secret";
        let key = b"This is my secret key\0\0\0\0\0\0\0\0\0\0\0";
        let encrypted = encrypt(*key, secret);
        let decrypted = decrypt(*key, encrypted.as_slice()).unwrap();
        assert_eq!(secret.to_vec(), decrypted);
    }
}
