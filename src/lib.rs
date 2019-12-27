//! Implementation of [Macaroons](http://research.google.com/pubs/pub41892.html) for Rust, which are
//! flexible authorization tokens for distributed systems. They are similar to cookies, but allow for
//! more narrowly-focused authorization based on contextual caveats. For more information, see
//! [here](https://raw.githubusercontent.com/rescrv/libmacaroons/master/README).
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
//! ```
//! use macaroon::{Macaroon, Verifier, MacaroonKey};
//!
//! // Initialize to make crypto primitives thread-safe
//! macaroon::initialize().unwrap(); // Force panic if initialization fails
//!
//! // Create our key
//! let key = "key".into();
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
//! let other_key = "different key".into();
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
//! # Supported Features
//! This crate supports all the following features:
//!
//! - verification of first-party caveats either via exact string match or passed-in function
//! - verification of third-party caveats using discharge macaroons (including ones that themselves have embedded third-party caveats)
//! - serialization and deserialization of caveats via version 1, 2 or 2J serialization formats (fully compatible with libmacaroons)
#[macro_use]
extern crate log;
extern crate base64;
extern crate serde;
extern crate serde_json;
extern crate sodiumoxide;

mod caveat;
pub mod crypto;
pub mod error;
mod serialization;
pub mod verifier;

pub use caveat::Caveat;
pub use crypto::MacaroonKey;
pub use error::MacaroonError;
pub use serialization::Format;
pub use verifier::Verifier;

use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

pub type Result<T> = std::result::Result<T, MacaroonError>;

/// Initializes the cryptographic libraries. Although you can use libmacaroon-rs without
/// calling this, the underlying random-number generator is not guaranteed to be thread-safe
/// if you don't.
pub fn initialize() -> Result<()> {
    match sodiumoxide::init() {
        Ok(_) => Ok(()),
        Err(_) => Err(MacaroonError::InitializationError),
    }
}

// An implementation that represents any binary data. By spec, most fields in a
// macaroon support binary encoded as base64, so ByteString has methods to
// convert to and from base64 strings
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteString(pub Vec<u8>);

impl AsRef<[u8]> for ByteString {
    fn as_ref(&self) -> &[u8] {
        &self.0
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

impl Default for ByteString {
    fn default() -> ByteString {
        ByteString(Default::default())
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

#[derive(Clone, Debug, PartialEq)]
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
    /// Returns `MacaroonError::BadMacaroon` if the identifier is is empty
    pub fn create(
        location: Option<String>,
        key: &MacaroonKey,
        identifier: ByteString,
    ) -> Result<Macaroon> {
        let macaroon: Macaroon = Macaroon {
            location,
            identifier: identifier.clone(),
            signature: crypto::hmac(key, &identifier),
            caveats: Vec::new(),
        };
        debug!("Macaroon::create: {:?}", macaroon);
        macaroon.validate()
    }

    /// Returns a clone of the identifier for the macaroon
    pub fn identifier(&self) -> ByteString {
        self.identifier.clone()
    }

    /// Returns the location for the macaroon
    pub fn location(&self) -> Option<String> {
        self.location.clone()
    }

    /// Returns the macaroon's signature
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
            .filter(|c| match c {
                caveat::Caveat::FirstParty(_) => true,
                _ => false,
            })
            .cloned()
            .collect()
    }

    /// Retrieve a list of the third-party caveats for the macaroon
    pub fn third_party_caveats(&self) -> Vec<Caveat> {
        self.caveats
            .iter()
            .filter(|c| match c {
                caveat::Caveat::ThirdParty(_) => true,
                _ => false,
            })
            .cloned()
            .collect()
    }

    /// Validate the macaroon - used mainly for validating deserialized macaroons
    fn validate(self) -> Result<Self> {
        if self.identifier.0.is_empty() {
            return Err(MacaroonError::BadMacaroon("No macaroon identifier"));
        }
        if self.signature.is_empty() {
            return Err(MacaroonError::BadMacaroon("No macaroon signature"));
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
        let vid: Vec<u8> = crypto::encrypt_key(&self.signature, key);
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
        let zero_key: MacaroonKey = [0; 32].into();
        discharge.signature = crypto::hmac2(&zero_key, &self.signature, &discharge.signature);
        debug!(
            "Macaroon::bind: original: {:?}, discharge: {:?}",
            self, discharge
        );
    }

    /// Serialize the macaroon using the serialization format provided
    pub fn serialize(&self, format: serialization::Format) -> Result<Vec<u8>> {
        match format {
            serialization::Format::V1 => serialization::v1::serialize(self),
            serialization::Format::V2 => serialization::v2::serialize(self),
            serialization::Format::V2JSON => serialization::v2json::serialize(self),
        }
    }

    /// Deserialize a macaroon
    pub fn deserialize(data: &[u8]) -> Result<Macaroon> {
        let macaroon: Macaroon = match data[0] as char {
            '{' => serialization::v2json::deserialize(data)?,
            '\x02' => serialization::v2::deserialize(data)?,
            'a'..='z' | 'A'..='Z' | '0'..='9' | '+' | '-' | '/' | '_' => {
                serialization::v1::deserialize(data)?
            }
            _ => return Err(MacaroonError::UnknownSerialization),
        };
        macaroon.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::ByteString;
    use super::Caveat;
    use super::Macaroon;
    use super::MacaroonKey;
    use Result;

    #[test]
    fn create_macaroon() {
        let signature: MacaroonKey = [
            118, 104, 143, 143, 101, 76, 166, 146, 84, 159, 42, 235, 57, 143, 191, 198, 87, 96, 27,
            165, 196, 100, 12, 178, 175, 29, 112, 1, 253, 179, 216, 58,
        ]
        .into();
        let key: MacaroonKey = b"this is a super duper secret key".into();
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
        let key: MacaroonKey = "this is a super duper secret key".into();
        let macaroon_res: Result<Macaroon> =
            Macaroon::create(Some("location".into()), &key, "".into());
        assert!(macaroon_res.is_err());
    }

    #[test]
    fn create_macaroon_with_first_party_caveat() {
        let signature: MacaroonKey = [
            68, 26, 16, 191, 99, 247, 36, 188, 53, 140, 17, 49, 218, 48, 129, 178, 14, 196, 187,
            82, 117, 4, 232, 42, 251, 131, 86, 98, 133, 201, 45, 6,
        ]
        .into();
        let key: MacaroonKey = b"this is a super duper secret key".into();
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
        let key: MacaroonKey = "this is a super duper secret key".into();
        let mut macaroon =
            Macaroon::create(Some("location".into()), &key, "identifier".into()).unwrap();
        let location = "https://auth.mybank.com";
        let cav_key: MacaroonKey = "My key".into();
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
}
