use crate::error::MacaroonError;
use crate::Result;
use sodiumoxide::crypto::auth::hmacsha256::{authenticate, gen_key, Key, Tag};
use sodiumoxide::crypto::secretbox;
use std::borrow::Borrow;
use std::ops::{Deref, DerefMut};

const KEY_GENERATOR: MacaroonKey = MacaroonKey(*b"macaroons-key-generator\0\0\0\0\0\0\0\0\0");

/// Secret cryptographic key used to sign and verify Macaroons.
///
/// This is a wrapper type around an array of bytes of the correct size for the underlying
/// cryptographic primatives (currently 32 bytes). Keys can be either provided verbatim as raw
/// bytes; generated randomly; or generated via an HMAC from a byte string of any length. For
/// security, keys should be generated using at least 32 bytes of entropy, and stored securely.
///
/// No special techniques are used by this crate to keep key material safe in memory. The `Debug`
/// trait will output the secret key material, which could end up leaked in logs.
///
/// ## Creation
///
/// ```rust
/// # use std::error::Error;
/// #
/// # fn main() -> Result<(), Box<dyn Error>> {
/// use macaroon::MacaroonKey;
/// extern crate base64;
///
/// // generate a new random key from scratch
/// let fresh_key = MacaroonKey::generate_random();
///
/// // generate from a byte string
/// let weak_example_key = MacaroonKey::generate(b"some-secret-here");
///
/// // import a base64-encoded key (eg, from a secrets vault)
/// let mut key_bytes: [u8; 32] = [0; 32];
/// key_bytes.copy_from_slice(&base64::decode("zV/IaqNgsWe2c22J5ilLY/d9DbxEir2z1bYBrzBemsM=")?);
/// let secret_key: MacaroonKey = key_bytes.into();
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacaroonKey([u8; sodiumoxide::crypto::auth::KEYBYTES]);

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

impl From<Key> for MacaroonKey {
    fn from(k: Key) -> Self {
        MacaroonKey(k.0)
    }
}

impl From<[u8; sodiumoxide::crypto::auth::KEYBYTES]> for MacaroonKey {
    /// Uses bytes directly as a MacaroonKey (with no HMAC)
    fn from(b: [u8; sodiumoxide::crypto::auth::KEYBYTES]) -> Self {
        MacaroonKey(b)
    }
}

impl From<&[u8; sodiumoxide::crypto::auth::KEYBYTES]> for MacaroonKey {
    /// Uses bytes directly as a MacaroonKey (with no HMAC)
    fn from(b: &[u8; sodiumoxide::crypto::auth::KEYBYTES]) -> Self {
        MacaroonKey(*b)
    }
}

impl MacaroonKey {
    /// Generate a new random key, using a secure random number generator.
    ///
    /// ```rust
    /// # use macaroon::MacaroonKey;
    /// let key = MacaroonKey::generate_random();
    /// ```
    pub fn generate_random() -> Self {
        MacaroonKey(gen_key().0)
    }

    /// Use some seed data to reproducibly generate a MacaroonKey via HMAC.
    ///
    /// ```rust
    /// # use macaroon::MacaroonKey;
    /// let key = MacaroonKey::generate(b"secret-byte-string");
    /// let key = MacaroonKey::generate("secret-unicode-string‽".as_bytes());
    ///
    /// let b = [5,4,3,2,1];
    /// let key = MacaroonKey::generate(&b);
    /// ```
    pub fn generate(seed: &[u8]) -> Self {
        generate_derived_key(seed)
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
    hmac(key, &tmp)
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
        return Err(MacaroonError::CryptoError("encrypted data too short"));
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
            .ok_or(MacaroonError::CryptoError(
                "supplied key has wrong length (expected 32 bytes)",
            ))?
            .into()),
        Err(()) => {
            error!(
                "crypto::decrypt: Unknown decryption error decrypting {:?}",
                raw_data
            );
            Err(MacaroonError::CryptoError("failed to decrypt ciphertext"))
        }
    }
}

#[cfg(test)]
mod test {
    use super::{decrypt_key, encrypt_key, MacaroonKey};

    #[test]
    fn test_encrypt_decrypt() {
        // NOTE: these are keys as byte sequences, not generated via HMAC
        let secret: MacaroonKey = b"This is my encrypted key\0\0\0\0\0\0\0\0".into();
        let key: MacaroonKey = b"This is my secret key\0\0\0\0\0\0\0\0\0\0\0".into();
        let encrypted = encrypt_key(&key, &secret);
        let decrypted = decrypt_key(&key, &encrypted).unwrap();
        assert_eq!(secret, decrypted);
    }
}
