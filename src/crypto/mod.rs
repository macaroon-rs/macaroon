use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use chacha20poly1305::aead::Aead;
use hmac::Hmac;
use rand::RngCore;
use sha2::Sha256;

use crate::crypto::key::*;
use crate::error::MacaroonError;
use crate::Result;

pub mod key;

pub type MacaroonHmac = Hmac<Sha256>;

pub trait Encryptor<T>
where
    T: AsRef<[u8; KEY_BYTES]> + ?Sized,
{
    fn encrypt(with_key: &T, clear_bytes: &[u8]) -> Result<Vec<u8>>;
}

pub trait Decryptor<T>
where
    T: AsRef<[u8; KEY_BYTES]> + ?Sized,
{
    fn decrypt(with_key: &T, cipher_bytes: &[u8]) -> Result<MacaroonKey>;
}


/// The default implementation of an Encryptor and Decryptor.
/// Uses Chacha20-Poly1305 AEAD
pub struct DefaultEncryptor<T: ?Sized> {
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Encryptor<T> for DefaultEncryptor<T>
where
    T: AsRef<[u8; KEY_BYTES]> + ?Sized,
{
    fn encrypt(with_key: &T, clear_bytes: &[u8]) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let mut nonce_bytes: [u8; NONCE_BYTES] = [0; NONCE_BYTES];
        rng.fill_bytes(&mut nonce_bytes);

        let key = Key::from_slice(with_key.as_ref());
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::from(nonce_bytes);

        let encrypted = cipher.encrypt(&nonce, clear_bytes)
            .expect("encrypt_macaroon_key: could not encrypt");

        let mut ret: Vec<u8> = Vec::new();
        ret.extend(nonce_bytes);
        ret.extend(encrypted);

        Ok(ret)
    }
}

impl<T> Decryptor<T> for DefaultEncryptor<T>
where
    T: AsRef<[u8; KEY_BYTES]> + ?Sized,
{
    fn decrypt(with_key: &T, cipher_bytes: &[u8]) -> Result<MacaroonKey> {
        let raw_data: &[u8] = cipher_bytes.as_ref();
        if raw_data.len() <= NONCE_BYTES + KEY_BYTES {
            println!("crypto::decrypt: Encrypted data too short ({})", raw_data.len());
            return Err(MacaroonError::CryptoError("Encrypted data too short"));
        }

        let mut nonce_bytes: [u8; NONCE_BYTES] = [0; NONCE_BYTES];
        nonce_bytes.clone_from_slice(&raw_data[..NONCE_BYTES]);

        let mut sealed: Vec<u8> = Vec::new();
        sealed.extend(&raw_data[NONCE_BYTES..]);

        let key = Key::from_slice(with_key.as_ref());
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::from(nonce_bytes);

        let decrypted = cipher.decrypt(&nonce, sealed.as_ref())
            .expect("decrypt_macaroon_key: could not decrypt");

        Ok(decrypted.into())
    }
}

#[cfg(test)]
mod test {
    use super::{Decryptor, DefaultEncryptor, Encryptor, MacaroonKey};

    #[test]
    fn test_encrypt_decrypt() {
        // NOTE: these are keys as byte sequences, not generated via HMAC
        let secret: MacaroonKey = b"This is my encrypted key\0\0\0\0\0\0\0\0".into();
        let key: MacaroonKey = b"This is my secret key\0\0\0\0\0\0\0\0\0\0\0".into();
        let encrypted = DefaultEncryptor::encrypt(&key, secret.as_ref()).unwrap();
        let decrypted = DefaultEncryptor::decrypt(&key, encrypted.as_ref()).unwrap();
        assert_eq!(secret, decrypted);
    }
}
