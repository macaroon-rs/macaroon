use std::borrow::Borrow;
use std::ops::{Deref, DerefMut};

use chacha20poly1305::aead::rand_core::RngCore;
use hmac::Mac;

use crate::crypto::{Decryptor, DefaultEncryptor, Encryptor, MacaroonHmac};

pub const NONCE_BYTES: usize = 12usize;
pub const KEY_BYTES: usize = 32usize;

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
pub struct MacaroonKey(pub [u8; KEY_BYTES]);

impl AsRef<[u8; KEY_BYTES]> for MacaroonKey {
    fn as_ref(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
}

impl AsRef<[u8]> for MacaroonKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Borrow<[u8; KEY_BYTES]> for MacaroonKey {
    fn borrow(&self) -> &[u8; KEY_BYTES] {
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

impl From<[u8; KEY_BYTES]> for MacaroonKey {
    /// Uses bytes directly as a MacaroonKey (with no HMAC)
    fn from(b: [u8; KEY_BYTES]) -> Self {
        MacaroonKey(b)
    }
}

impl From<&[u8; KEY_BYTES]> for MacaroonKey {
    /// Uses bytes directly as a MacaroonKey (with no HMAC)
    fn from(b: &[u8; KEY_BYTES]) -> Self {
        MacaroonKey(*b)
    }
}

impl From<Vec<u8>> for MacaroonKey {
    fn from(bytes: Vec<u8>) -> Self {
        if bytes.len() < KEY_BYTES {
            panic!("invalid key size {} != {}", bytes.len(), KEY_BYTES)
        }

        let mut ret: [u8; KEY_BYTES] = [0; KEY_BYTES];
        for (i, b) in bytes.iter().enumerate() {
            if i == KEY_BYTES {
                break;
            }
            ret[i] = *b;
        }
        MacaroonKey(ret)
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
        let mut rng = rand::thread_rng();
        let mut key: [u8; KEY_BYTES] = [0; KEY_BYTES];
        rng.fill_bytes(&mut key);
        MacaroonKey(key)
        // MacaroonKey(MacaroonHmac::generate_key(rng).into())
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
    T: AsRef<[u8; KEY_BYTES]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    let mut mac = <MacaroonHmac as Mac>::new_from_slice(key.as_ref())
        .expect("could not create Hmac");
    mac.update(text.as_ref());
    let bytes = mac.finalize().into_bytes().to_vec();
    bytes.into()
}

pub fn hmac2<T, U>(key: &T, text1: &U, text2: &U) -> MacaroonKey
where
    T: AsRef<[u8; KEY_BYTES]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    let MacaroonKey(tmp1) = hmac(key, text1);
    let MacaroonKey(tmp2) = hmac(key, text2);
    let tmp = [tmp1, tmp2].concat();
    hmac(key, &tmp)
}

pub fn encrypt_key<T>(key: &T, plaintext: &T) -> Vec<u8>
where
    T: AsRef<[u8; KEY_BYTES]> + ?Sized
{
    DefaultEncryptor::encrypt(key, plaintext.as_ref()).unwrap()
}

pub fn decrypt_key<T, U>(key: &T, data: &U) -> crate::Result<MacaroonKey>
where
    T: AsRef<[u8; KEY_BYTES]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    DefaultEncryptor::decrypt(key, data.as_ref())
}
