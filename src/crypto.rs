use crate::error::MacaroonError;
use crate::Result;
use sodiumoxide::crypto::auth::hmacsha512256::{authenticate, gen_key, Key, Tag};
use sodiumoxide::crypto::secretbox;
use std::borrow::Borrow;
use std::ops::{Deref, DerefMut};

const KEY_GENERATOR: MacaroonKey = MacaroonKey(*b"macaroons-key-generator\0\0\0\0\0\0\0\0\0");

// A convenience type for a MacaroonKey with helpful methods attached for
// conversion. Using the default trait will return a randomly generated key
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MacaroonKey([u8; sodiumoxide::crypto::auth::KEYBYTES]);

impl Default for MacaroonKey {
    fn default() -> Self {
        MacaroonKey(gen_key().0)
    }
}

impl AsRef<[u8; sodiumoxide::crypto::auth::KEYBYTES]> for MacaroonKey {
    fn as_ref(&self) -> &[u8; sodiumoxide::crypto::auth::KEYBYTES] {
        &self.0
    }
}

impl AsRef<[u8]> for MacaroonKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Borrow<[u8; sodiumoxide::crypto::auth::KEYBYTES]> for MacaroonKey {
    fn borrow(&self) -> &[u8; sodiumoxide::crypto::auth::KEYBYTES] {
        &self.0
    }
}

impl Deref for MacaroonKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for MacaroonKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<&str> for MacaroonKey {
    fn from(s: &str) -> Self {
        generate_derived_key(s.as_bytes())
    }
}

impl From<&[u8]> for MacaroonKey {
    fn from(b: &[u8]) -> Self {
        generate_derived_key(b)
    }
}

impl From<Key> for MacaroonKey {
    fn from(k: Key) -> Self {
        MacaroonKey(k.0)
    }
}

impl From<[u8; sodiumoxide::crypto::auth::KEYBYTES]> for MacaroonKey {
    fn from(b: [u8; sodiumoxide::crypto::auth::KEYBYTES]) -> Self {
        MacaroonKey(b)
    }
}

impl From<&[u8; sodiumoxide::crypto::auth::KEYBYTES]> for MacaroonKey {
    fn from(b: &[u8; sodiumoxide::crypto::auth::KEYBYTES]) -> Self {
        MacaroonKey(*b)
    }
}

fn generate_derived_key(key: &[u8]) -> MacaroonKey {
    hmac(&KEY_GENERATOR, key)
}

pub fn hmac<T, U>(key: &T, text: &U) -> MacaroonKey
where
    T: AsRef<[u8; sodiumoxide::crypto::auth::KEYBYTES]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    let Tag(result_bytes) = authenticate(text.as_ref(), &Key(*key.as_ref()));
    MacaroonKey(result_bytes)
}

pub fn hmac2<T, U>(key: &T, text1: &U, text2: &U) -> MacaroonKey
where
    T: AsRef<[u8; sodiumoxide::crypto::auth::KEYBYTES]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    let MacaroonKey(tmp1) = hmac(key, text1);
    let MacaroonKey(tmp2) = hmac(key, text2);
    let tmp = [tmp1, tmp2].concat();
    hmac(key, &tmp.to_vec())
}

pub fn encrypt_key<T>(key: &T, plaintext: &T) -> Vec<u8>
where
    T: AsRef<[u8; sodiumoxide::crypto::auth::KEYBYTES]> + ?Sized,
{
    let nonce = secretbox::gen_nonce();
    let encrypted = secretbox::seal(plaintext.as_ref(), &nonce, &secretbox::Key(*key.as_ref()));
    let mut ret: Vec<u8> = Vec::new();
    ret.extend(&nonce.0);
    ret.extend(encrypted);
    ret
}

pub fn decrypt_key<T, U>(key: &T, data: &U) -> Result<MacaroonKey>
where
    T: AsRef<[u8; sodiumoxide::crypto::auth::KEYBYTES]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    let raw_data: &[u8] = data.as_ref();
    if raw_data.len() <= secretbox::NONCEBYTES + secretbox::MACBYTES {
        error!("crypto::decrypt: Encrypted data {:?} too short", raw_data);
        return Err(MacaroonError::DecryptionError("Encrypted data too short"));
    }
    let mut nonce: [u8; secretbox::NONCEBYTES] = [0; secretbox::NONCEBYTES];
    nonce.clone_from_slice(&raw_data[..secretbox::NONCEBYTES]);
    let mut temp: Vec<u8> = Vec::new();
    temp.extend(&raw_data[secretbox::NONCEBYTES..]);
    let ciphertext = temp.as_slice();
    match secretbox::open(
        ciphertext,
        &secretbox::Nonce(nonce),
        &secretbox::Key(*key.as_ref()),
    ) {
        Ok(plaintext) => Ok(Key::from_slice(&plaintext)
            .ok_or(MacaroonError::DecryptionError(
                "given key is incorrect length",
            ))?
            .into()),
        Err(()) => {
            error!(
                "crypto::decrypt: Unknown decryption error decrypting {:?}",
                raw_data
            );
            Err(MacaroonError::DecryptionError("Unknown decryption error"))
        }
    }
}

#[cfg(test)]
mod test {
    use super::{decrypt_key, encrypt_key, MacaroonKey};

    #[test]
    fn test_encrypt_decrypt() {
        let secret: MacaroonKey = "This is my encrypted key\0\0\0\0\0\0\0\0".into();
        let key: MacaroonKey = "This is my secret key\0\0\0\0\0\0\0\0\0\0\0".into();
        let encrypted = encrypt_key(&key, &secret);
        let decrypted = decrypt_key(&key, &encrypted).unwrap();
        assert_eq!(secret, decrypted);
    }
}
