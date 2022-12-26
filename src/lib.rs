//! Implementation of [Macaroons](http://research.google.com/pubs/pub41892.html) for Rust, which are
//! flexible authorization tokens for distributed systems. They are similar to cookies, but allow for
//! more narrowly-focused authorization based on contextual caveats.
//!
//! # What Are Macaroons?
//!
//! Macaroons are bearer tokens (similar to cookies) which encode within them criteria within which the
//! authorization is allowed to take place (referred to as "caveats"). For instance, authorization could
//! be restricted to a particular user, account, time of day, really anything. These criteria can be either
//! evaluated locally (a "first-party caveat"), or using special macaroons ("discharge macaroons") generated
//! by a third party (a "third-party caveat").
//!
//! A first-party caveat consists simply of a predicate which, when evaluated as true, authorizes the caveat.
//! The predicate is a string which is either evaluated using strict string comparison (`satisfy_exact`),
//! or interpreted using a provided function (`satisfy_general`).
//!
//! A third-party caveat consists of a location string, an identifier, and a specially-generated signing key
//! to authenticate the generated discharge macaroons. The key and identifier is passed to the third-party
//! who generates the discharge macaroons. The receiver then binds each discharge macaroon to the original
//! macaroon.
//!
//! During verification of a third-party caveat, a discharge macaroon is found from those received whose identifier
//! matches that of the caveat. The binding signature is verified, and the discharge macaroon's caveats are verified
//! using the same process as the original macaroon.
//!
//! The macaroon is considered authorized only if all its caveats are authorized by the above process.
//!
//! # Example
//!
//! ```rust
//! use macaroon::{Macaroon, Verifier, MacaroonKey};
//!
//! // Initialize to make crypto primitives thread-safe
//! macaroon::initialize().unwrap(); // Force panic if initialization fails
//!
//! // Create our key
//! let key = MacaroonKey::generate(b"key");
//!
//! // Create our macaroon. A location is optional.
//! let mut macaroon = match Macaroon::create(Some("location".into()), &key, "id".into()) {
//!     Ok(macaroon) => macaroon,
//!     Err(error) => panic!("Error creating macaroon: {:?}", error),
//! };
//!
//! // Add our first-party caveat. We say that only someone with account 12345678
//! // is authorized to access whatever the macaroon is protecting
//! // Note that we can add however many of these we want, with different predicates
//! macaroon.add_first_party_caveat("account = 12345678".into());
//!
//! // Now we verify the macaroon
//! // First we create the verifier
//! let mut verifier = Verifier::default();
//!
//! // We assert that the account number is "12345678"
//! verifier.satisfy_exact("account = 12345678".into());
//!
//! // Now we verify the macaroon. It should return `Ok(true)` if the user is authorized
//! match verifier.verify(&macaroon, &key, Default::default()) {
//!     Ok(_) => println!("Macaroon verified!"),
//!     Err(error) => println!("Error validating macaroon: {:?}", error),
//! }
//!
//! // Now, let's add a third-party caveat, which just says that we need our third party
//! // to authorize this for us as well.
//!
//! // Create a key for the third party caveat
//! let other_key = MacaroonKey::generate(b"different key");
//!
//! macaroon.add_third_party_caveat("https://auth.mybank", &other_key, "caveat id".into());
//!
//! // When we're ready to verify a third-party caveat, we use the location
//! // (in this case, "https://auth.mybank") to retrieve the discharge macaroons we use to verify.
//! // These would be created by the third party like so:
//! let mut discharge = match Macaroon::create(Some("http://auth.mybank/".into()),
//!                                            &other_key,
//!                                            "caveat id".into()) {
//!     Ok(discharge) => discharge,
//!     Err(error) => panic!("Error creating discharge macaroon: {:?}", error),
//! };
//! // And this is the criterion the third party requires for authorization
//! discharge.add_first_party_caveat("account = 12345678".into());
//!
//! // Once we receive the discharge macaroon, we bind it to the original macaroon
//! macaroon.bind(&mut discharge);
//!
//! // Then we can verify using the same verifier (which will verify both the existing
//! // first-party caveat and the third party one)
//! match verifier.verify(&macaroon, &key, vec![discharge]) {
//!     Ok(_) => println!("Macaroon verified!"),
//!     Err(error) => println!("Error validating macaroon: {:?}", error),
//! }
//! ```
//!
//! # Supported Features
//!
//! This crate supports all the following features:
//!
//! - verification of first-party caveats either via exact string match or passed-in function
//! - verification of third-party caveats using discharge macaroons (including ones that themselves have embedded third-party caveats)
//! - serialization and deserialization of caveats via version 1, 2 or 2J serialization formats (fully compatible with libmacaroons)

use std::fmt;

use log::debug;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Visitor;

pub use crate::caveat::Caveat;
pub use crate::crypto::key::MacaroonKey;
pub use crate::error::MacaroonError;
pub use crate::serialization::Format;
pub use crate::verifier::{Verifier, VerifyFunc};

mod caveat;
mod crypto;
mod error;
mod serialization;
mod verifier;

const URL_SAFE_ENGINE: base64::engine::fast_portable::FastPortable =
    base64::engine::fast_portable::FastPortable::from(
        &base64::alphabet::URL_SAFE,
        base64::engine::fast_portable::PAD);
const STANDARD_ENGINE: base64::engine::fast_portable::FastPortable =
    base64::engine::fast_portable::FastPortable::from(
        &base64::alphabet::STANDARD,
        base64::engine::fast_portable::PAD);

pub type Result<T> = std::result::Result<T, MacaroonError>;

// An implementation that represents any binary data. By spec, most fields in a
// macaroon support binary encoded as base64, so ByteString has methods to
// convert to and from base64 strings
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ByteString(pub Vec<u8>);

impl AsRef<[u8]> for ByteString {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for ByteString {
    fn from(v: Vec<u8>) -> ByteString {
        ByteString(v)
    }
}

impl From<&[u8]> for ByteString {
    fn from(s: &[u8]) -> ByteString {
        ByteString(s.to_vec())
    }
}

impl From<&str> for ByteString {
    fn from(s: &str) -> ByteString {
        ByteString(s.as_bytes().to_vec())
    }
}

impl From<String> for ByteString {
    fn from(s: String) -> ByteString {
        ByteString(s.as_bytes().to_vec())
    }
}

impl From<[u8; 32]> for ByteString {
    fn from(b: [u8; 32]) -> ByteString {
        ByteString(b.to_vec())
    }
}

impl From<MacaroonKey> for ByteString {
    fn from(k: MacaroonKey) -> ByteString {
        ByteString(k.to_vec())
    }
}

impl fmt::Display for ByteString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base64::encode(&self.0))
    }
}

impl Serialize for ByteString {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

struct ByteStringVisitor;

impl<'de> Visitor<'de> for ByteStringVisitor {
    type Value = ByteString;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("base64 encoded string of bytes")
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let raw = match base64::decode(value) {
            Ok(v) => v,
            Err(_) => return Err(E::custom("unable to base64 decode value")),
        };
        Ok(ByteString(raw))
    }
}

impl<'de> Deserialize<'de> for ByteString {
    fn deserialize<D>(deserializer: D) -> std::result::Result<ByteString, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(ByteStringVisitor)
    }
}

/// Internal helper to decode base64 tokens in either URL-safe or non-URL-safe format, with or
/// without padding. The macaroons format specifies that macaroons should be accepted in any of
/// these variations.
///
/// Logic is based on pymacaroons helper:
/// https://github.com/ecordell/pymacaroons/blob/master/pymacaroons/utils.py#L109
fn base64_decode_flexible(b: &[u8]) -> Result<Vec<u8>> {
    if b.is_empty() {
        return Err(MacaroonError::DeserializationError(
            "empty token to deserialize".to_string(),
        ));
    }
    if b.contains(&b'_') || b.contains(&b'-') {
        Ok(base64::decode_engine(b, &URL_SAFE_ENGINE)?)
    } else {
        Ok(base64::decode_engine(b, &STANDARD_ENGINE)?)
    }
}

// https://github.com/rescrv/libmacaroons/blob/master/doc/format.txt#L87
#[test]
fn test_base64_decode_flexible() {
    let val = b"Ou?T".to_vec();
    assert_eq!(val, base64_decode_flexible(b"T3U/VA==").unwrap());
    assert_eq!(val, base64_decode_flexible(b"T3U_VA==").unwrap());
    assert_eq!(val, base64_decode_flexible(b"T3U/VA").unwrap());
    assert_eq!(val, base64_decode_flexible(b"T3U_VA").unwrap());

    assert!(base64_decode_flexible(b"...").is_err());
    assert!(base64_decode_flexible(b"").is_err());
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Macaroon {
    identifier: ByteString,
    location: Option<String>,
    signature: MacaroonKey,
    caveats: Vec<Caveat>,
}

impl Macaroon {
    /// Construct a macaroon, given a location and identifier, and a key to sign
    /// it with. You can use a bare str or &[u8] containing arbitrary data with
    /// `into` to automatically generate a suitable key
    ///
    /// # Errors
    ///
    /// Returns `MacaroonError::IncompleteMacaroon` if the identifier bytestring is empty
    pub fn create(
        location: Option<String>,
        key: &MacaroonKey,
        identifier: ByteString,
    ) -> Result<Macaroon> {
        let macaroon: Macaroon = Macaroon {
            location,
            identifier: identifier.clone(),
            signature: crypto::key::hmac(key, &identifier),
            caveats: Vec::new(),
        };
        debug!("Macaroon::create: {:?}", macaroon);
        macaroon.validate()
    }

    /// Returns a clone of the identifier for the macaroon
    pub fn identifier(&self) -> ByteString {
        self.identifier.clone()
    }

    /// Returns a clone the location for the macaroon
    pub fn location(&self) -> Option<String> {
        self.location.clone()
    }

    /// Returns the macaroon's signature
    ///
    /// The [MacaroonKey] type is used because it is the same size and format a signature, but the
    /// signature is not and should be used as a cryptographic key.
    pub fn signature(&self) -> MacaroonKey {
        self.signature
    }

    pub fn caveats(&self) -> Vec<Caveat> {
        self.caveats.clone()
    }

    /// Retrieve a list of the first-party caveats for the macaroon
    pub fn first_party_caveats(&self) -> Vec<Caveat> {
        self.caveats
            .iter()
            .filter(|c| matches!(c, caveat::Caveat::FirstParty(_)))
            .cloned()
            .collect()
    }

    /// Retrieve a list of the third-party caveats for the macaroon
    pub fn third_party_caveats(&self) -> Vec<Caveat> {
        self.caveats
            .iter()
            .filter(|c| matches!(c, caveat::Caveat::ThirdParty(_)))
            .cloned()
            .collect()
    }

    /// Validate that a Macaroon has all the expected fields
    ///
    /// This is a low-level function to confirm that a macaroon was constructured correctly. It
    /// does *not* verify the signature, caveats, or in any way confirm that a macaroon is
    /// authentic from a security standpoint.
    fn validate(self) -> Result<Self> {
        if self.identifier.0.is_empty() {
            return Err(MacaroonError::IncompleteMacaroon("no identifier found"));
        }
        if self.signature.is_empty() {
            return Err(MacaroonError::IncompleteMacaroon("no signature found"));
        }

        Ok(self)
    }

    /// Add a first-party caveat to the macaroon
    ///
    /// A first-party caveat is just a string predicate in some
    /// DSL which can be verified either by exact string match,
    /// or by using a function to parse the string and validate it
    /// (see Verifier for more info).
    pub fn add_first_party_caveat(&mut self, predicate: ByteString) {
        let caveat: caveat::Caveat = caveat::new_first_party(predicate);
        self.signature = caveat.sign(&self.signature);
        self.caveats.push(caveat);
        debug!("Macaroon::add_first_party_caveat: {:?}", self);
    }

    /// Add a third-party caveat to the macaroon
    ///
    /// A third-party caveat is a caveat which must be verified by a third party
    /// using macaroons provided by them (referred to as "discharge macaroons").
    pub fn add_third_party_caveat(&mut self, location: &str, key: &MacaroonKey, id: ByteString) {
        let vid: Vec<u8> = crypto::key::encrypt_key(&self.signature, key);
        let caveat: caveat::Caveat = caveat::new_third_party(id, ByteString(vid), location);
        self.signature = caveat.sign(&self.signature);
        self.caveats.push(caveat);
        debug!("Macaroon::add_third_party_caveat: {:?}", self);
    }

    /// Bind a discharge macaroon to the original macaroon
    ///
    /// When a macaroon with third-party caveats must be authorized, you send off to the various
    /// locations specified in the caveats, sending the caveat ID and key, and receive a set
    /// of one or more "discharge macaroons" which are used to verify the caveat. In order to ensure
    /// that the discharge macaroons aren't re-used in some other context, we bind them to the original
    /// macaroon so that they can't be used in a different context.
    pub fn bind(&self, discharge: &mut Macaroon) {
        let zero_key = MacaroonKey::from([0; 32]);
        discharge.signature = crypto::key::hmac2(&zero_key, &self.signature, &discharge.signature);
        debug!(
            "Macaroon::bind: original: {:?}, discharge: {:?}",
            self, discharge
        );
    }

    /// Serialize the macaroon using the serialization [Format] provided
    ///
    /// For V1 and V2, the binary format will be encoded as URL-safe base64 with padding
    /// (`base64::URL_SAFE`). For V2JSON, the output will be JSON.
    pub fn serialize(&self, format: serialization::Format) -> Result<String> {
        match format {
            serialization::Format::V1 => serialization::v1::serialize(self),
            serialization::Format::V2 => serialization::v2::serialize(self),
            serialization::Format::V2JSON => serialization::v2json::serialize(self),
        }
    }

    /// Deserialize an encoded macaroon token, inferring the [Format].
    ///
    /// For V1 and V2 tokens, this assumes base64 encoding, in either "standard" or URL-safe
    /// encoding, with or without padding.
    ///
    /// For V2JSON tokens, the token must begin with the `{` character with no preceeding whitespace.
    ///
    /// ## Usage
    ///
    /// ```rust
    /// use macaroon::Macaroon;
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    ///
    /// // '&str' gets automatically de-referenced to bytes ('&[u8]').
    /// // 'b"byte-string"' or slice of 'u8' would also work.
    /// let mac = Macaroon::deserialize("MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxNmNpZCB0ZXN0ID0gY2F2ZWF0CjAwMmZzaWduYXR1cmUgGXusegRK8zMyhluSZuJtSTvdZopmDkTYjOGpmMI9vWcK")?;
    ///
    /// let mac_v2json = Macaroon::deserialize(r#"{"v":2,"l":"http://example.org/","i":"keyid", "c":[{"i":"account = 3735928559"},{"i":"user = alice"}],"s64": "S-lnzR6gxrJrr2pKlO6bBbFYhtoLqF6MQqk8jQ4SXvw"}"#)?;
    ///
    /// // expect this to fail; leading whitespace is not allowed
    /// Macaroon::deserialize(r#"   {"v":2,"l":"http://example.org/","i":"keyid", "c":[{"i":"account = 3735928559"},{"i":"user = alice"}],"s64": "S-lnzR6gxrJrr2pKlO6bBbFYhtoLqF6MQqk8jQ4SXvw"}"#).unwrap_err();
    /// # Ok(()) }
    /// ```
    pub fn deserialize<T: AsRef<[u8]>>(token: T) -> Result<Macaroon> {
        if token.as_ref().is_empty() {
            return Err(MacaroonError::DeserializationError(
                "empty token provided".to_string(),
            ));
        }
        let mac: Macaroon = match token.as_ref()[0] as char {
            '{' => serialization::v2json::deserialize(token.as_ref())?,
            _ => {
                let binary = base64_decode_flexible(token.as_ref())?;
                Macaroon::deserialize_binary(&binary)?
            }
        };
        mac.validate()
    }

    /// Deserialize a binary macaroon token in binary, inferring the [Format]
    ///
    /// This works with V1 and V2 tokens, with no base64 encoding. It does not make sense to use
    /// this with V2JSON tokens.
    pub fn deserialize_binary(token: &[u8]) -> Result<Macaroon> {
        if token.is_empty() {
            return Err(MacaroonError::DeserializationError(
                "empty macaroon token".to_string(),
            ));
        }
        let mac: Macaroon = match token[0] as char {
            '\x02' => serialization::v2::deserialize(token)?,
            'a'..='f' | 'A'..='Z' | '0'..='9' => serialization::v1::deserialize(token)?,
            _ => {
                return Err(MacaroonError::DeserializationError(
                    "unknown macaroon serialization format".to_string(),
                ))
            }
        };
        mac.validate()
    }
}

#[cfg(test)]
mod tests {
    use crate::{ByteString, Caveat, Macaroon, MacaroonError, MacaroonKey, Result, Verifier};

    #[test]
    fn create_macaroon() {
        let signature: MacaroonKey = [
            20, 248, 23, 46, 70, 227, 253, 33, 123, 35, 116, 236, 130, 131, 211, 16, 41, 184, 51,
            65, 213, 46, 109, 76, 49, 201, 186, 92, 114, 163, 214, 231,
        ]
        .into();
        // NOTE: using byte string directly, not generating with HMAC
        let key = MacaroonKey::from(b"this is a super duper secret key");
        let macaroon_res = Macaroon::create(Some("location".into()), &key, "identifier".into());
        assert!(macaroon_res.is_ok());
        let macaroon = macaroon_res.unwrap();
        assert!(macaroon.location.is_some());
        assert_eq!("location", macaroon.location.unwrap());
        assert_eq!(ByteString::from("identifier"), macaroon.identifier);
        assert_eq!(signature, macaroon.signature);
        assert_eq!(0, macaroon.caveats.len());
    }

    #[test]
    fn create_invalid_macaroon() {
        // NOTE: using byte string directly, not generating with HMAC
        let key = MacaroonKey::from(b"this is a super duper secret key");
        let macaroon_res: Result<Macaroon> =
            Macaroon::create(Some("location".into()), &key, "".into());
        assert!(macaroon_res.is_err());
        assert!(matches!(
            macaroon_res,
            Err(MacaroonError::IncompleteMacaroon(_))
        ));
        println!("{}", macaroon_res.unwrap_err());
    }

    #[test]
    fn create_macaroon_errors() {
        let deser_err = Macaroon::deserialize(b"\0");
        assert!(matches!(
            deser_err,
            Err(MacaroonError::DeserializationError(_))
        ));
        println!("{}", deser_err.unwrap_err());

        let key = MacaroonKey::generate(b"this is a super duper secret key");
        let mut mac =
            Macaroon::create(Some("http://mybank".into()), &key, "identifier".into()).unwrap();

        let mut ver = Verifier::default();
        let wrong_key = MacaroonKey::generate(b"not what was expected");
        let sig_err = ver.verify(&mac, &wrong_key, Default::default());
        assert!(matches!(sig_err, Err(MacaroonError::InvalidSignature)));
        println!("{}", sig_err.unwrap_err());
        assert!(ver.verify(&mac, &key, Default::default()).is_ok());

        mac.add_first_party_caveat("account = 3735928559".into());
        let cav_err = ver.verify(&mac, &key, Default::default());
        assert!(matches!(cav_err, Err(MacaroonError::CaveatNotSatisfied(_))));
        println!("{}", cav_err.unwrap_err());
        ver.satisfy_exact("account = 3735928559".into());
        assert!(ver.verify(&mac, &key, Default::default()).is_ok());

        let mut mac2 = mac.clone();
        let cav_key = MacaroonKey::generate(b"My key");
        mac2.add_third_party_caveat("other location", &cav_key, "other ident".into());
        let cav_err = ver.verify(&mac2, &key, Default::default());
        assert!(matches!(cav_err, Err(MacaroonError::CaveatNotSatisfied(_))));
        println!("{}", cav_err.unwrap_err());

        let discharge = Macaroon::create(
            Some("http://auth.mybank/".into()),
            &cav_key,
            "other keyid".into(),
        )
        .unwrap();
        let disch_err = ver.verify(&mac, &key, vec![discharge]);
        assert!(matches!(disch_err, Err(MacaroonError::DischargeNotUsed)));
        println!("{}", disch_err.unwrap_err());
    }

    #[test]
    fn create_macaroon_with_first_party_caveat() {
        let signature: MacaroonKey = [
            14, 23, 21, 148, 48, 224, 4, 143, 81, 137, 60, 25, 201, 198, 245, 250, 249, 62, 233,
            94, 93, 65, 247, 88, 25, 39, 170, 203, 8, 4, 167, 187,
        ]
        .into();
        // NOTE: using byte string directly, not generating with HMAC
        let key = MacaroonKey::from(b"this is a super duper secret key");
        let mut macaroon =
            Macaroon::create(Some("location".into()), &key, "identifier".into()).unwrap();
        macaroon.add_first_party_caveat("predicate".into());
        assert_eq!(1, macaroon.caveats.len());
        let predicate = match &macaroon.caveats[0] {
            Caveat::FirstParty(fp) => fp.predicate(),
            _ => ByteString::default(),
        };
        assert_eq!(ByteString::from("predicate"), predicate);
        assert_eq!(signature, macaroon.signature);
        assert_eq!(&macaroon.caveats[0], &macaroon.first_party_caveats()[0]);
    }

    #[test]
    fn create_macaroon_with_third_party_caveat() {
        // NOTE: using byte string directly, not generating with HMAC
        let key = MacaroonKey::from(b"this is a super duper secret key");
        let mut macaroon =
            Macaroon::create(Some("location".into()), &key, "identifier".into()).unwrap();
        let location = "https://auth.mybank.com";
        let cav_key = MacaroonKey::generate(b"My key");
        let id = "My Caveat";
        macaroon.add_third_party_caveat(location, &cav_key, id.into());
        assert_eq!(1, macaroon.caveats.len());
        let cav_id = match &macaroon.caveats[0] {
            Caveat::ThirdParty(tp) => tp.id(),
            _ => ByteString::default(),
        };
        let cav_location = match &macaroon.caveats[0] {
            Caveat::ThirdParty(tp) => tp.location(),
            _ => String::default(),
        };
        assert_eq!(location, cav_location);
        assert_eq!(ByteString::from(id), cav_id);
        assert_eq!(&macaroon.caveats[0], &macaroon.third_party_caveats()[0]);
    }

    #[test]
    fn test_deserialize_bad_data() {
        // these are all expected to fail... but not panic!
        assert!(Macaroon::deserialize(b"").is_err());
        assert!(Macaroon::deserialize(b"12345").is_err());
        assert!(Macaroon::deserialize(b"\0").is_err());
        assert!(Macaroon::deserialize(b"NDhJe_A==").is_err());

        // examples that fail from fuzzing for the top-level deserialize function
        assert!(Macaroon::deserialize(&vec![10]).is_err());
        assert!(Macaroon::deserialize(&vec![70, 70, 102, 70]).is_err());
        assert!(Macaroon::deserialize(&vec![2, 2, 212, 212, 212, 212]).is_err());
    }
}

// This will run rust code in the README as a test. Copied from:
// https://github.com/rust-lang/cargo/issues/383#issuecomment-720873790
#[cfg(doctest)]
mod test_readme {
    macro_rules! external_doc_test {
        ($x:expr) => {
            #[doc = $x]
            extern "C" {}
        };
    }

    external_doc_test!(include_str!("../README.md"));
}
