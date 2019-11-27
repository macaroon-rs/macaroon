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
//! use macaroon::{Macaroon, Verifier};
//!
//! // Initialize to make crypto primitives thread-safe
//! macaroon::initialize().unwrap(); // Force panic if initialization fails
//!
//! // Create our macaroon
//! let mut macaroon = match Macaroon::create("location", b"key", "id") {
//!     Ok(macaroon) => macaroon,
//!     Err(error) => panic!("Error creating macaroon: {:?}", error),
//! };
//!
//! // Add our first-party caveat. We say that only someone with account 12345678
//! // is authorized to access whatever the macaroon is protecting
//! // Note that we can add however many of these we want, with different predicates
//! macaroon.add_first_party_caveat("account = 12345678");
//!
//! // Now we verify the macaroon
//! // First we create the verifier
//! let mut verifier = Verifier::new();
//!
//! // We assert that the account number is "12345678"
//! verifier.satisfy_exact("account = 12345678");
//!
//! // Now we verify the macaroon. It should return `Ok(true)` if the user is authorized
//! match macaroon.verify(b"key", &mut verifier) {
//!     Ok(true) => println!("Macaroon verified!"),
//!     Ok(false) => println!("Macaroon verification failed"),
//!     Err(error) => println!("Error validating macaroon: {:?}", error),
//! }
//!
//! // Now, let's add a third-party caveat, which just says that we need our third party
//! // to authorize this for us as well.
//! macaroon.add_third_party_caveat("https://auth.mybank", b"different key", "caveat id");
//!
//! // When we're ready to verify a third-party caveat, we use the location
//! // (in this case, "https://auth.mybank") to retrieve the discharge macaroons we use to verify.
//! // These would be created by the third party like so:
//! let mut discharge = match Macaroon::create("http://auth.mybank/",
//!                                            b"different key",
//!                                            "caveat id") {
//!     Ok(discharge) => discharge,
//!     Err(error) => panic!("Error creating discharge macaroon: {:?}", error),
//! };
//! // And this is the criterion the third party requires for authorization
//! discharge.add_first_party_caveat("account = 12345678");
//!
//! // Once we receive the discharge macaroon, we bind it to the original macaroon
//! macaroon.bind(&mut discharge);
//!
//! // Then we can verify using the same verifier (which will verify both the existing
//! // first-party caveat and the third party one)
//! verifier.add_discharge_macaroons(&vec![discharge]);
//! match macaroon.verify(b"key", &mut verifier) {
//!     Ok(true) => println!("Macaroon verified!"),
//!     Ok(false) => println!("Macaroon verification failed"),
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
extern crate rustc_serialize as serialize;
extern crate sodiumoxide;
extern crate serde;
extern crate serde_json;

mod caveat;
mod crypto;
pub mod error;
mod serialization;
pub mod verifier;

pub use caveat::{FirstPartyCaveat, ThirdPartyCaveat};
pub use verifier::Verifier;
pub use error::MacaroonError;
pub use serialization::Format;

use caveat::{Caveat, CaveatType};

/// Initializes the cryptographic libraries. Although you can use libmacaroon-rs without
/// calling this, the underlying random-number generator is not guaranteed to be thread-safe
/// if you don't.
pub fn initialize() -> Result<(), MacaroonError> {
    match sodiumoxide::init() {
        Ok(_) => return Ok(()),
        Err(_) => return Err(MacaroonError::InitializationError)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Macaroon {
    identifier: String,
    location: Option<String>,
    signature: [u8; 32],
    caveats: Vec<Box<dyn Caveat>>,
}

impl Macaroon {
    /// Construct a macaroon, given a location and identifier, and a key to sign it with
    ///
    /// # Errors
    /// Returns `MacaroonError::BadMacaroon` if the identifier is is empty
    pub fn create<'r>(location: &'r str,
                      key: &[u8],
                      identifier: &'r str)
                      -> Result<Macaroon, MacaroonError> {
        let macaroon_key = crypto::generate_derived_key(key);

        let macaroon: Macaroon = Macaroon {
            location: Some(String::from(location)),
            identifier: String::from(identifier),
            signature: crypto::generate_signature(&macaroon_key, identifier),
            caveats: Vec::new(),
        };
        debug!("Macaroon::create: {:?}", macaroon);
        macaroon.validate()
    }

    /// Returns the identifier for the macaroon
    pub fn identifier(&self) -> &String {
        &self.identifier
    }

    /// Returns the location for the macaroon
    pub fn location(&self) -> Option<String> {
        self.location.clone()
    }

    /// Returns the macaroon's signature
    pub fn signature(&self) -> &[u8; 32] {
        &self.signature
    }

    fn caveats(&self) -> &Vec<Box<dyn Caveat>> {
        &self.caveats
    }

    /// Retrieve a list of the first-party caveats for the macaroon
    pub fn first_party_caveats(&self) -> Vec<FirstPartyCaveat> {
        self.caveats
            .iter()
            .filter(|c| c.get_type() == CaveatType::FirstParty)
            .map(|c| c.as_first_party().unwrap().clone())
            .collect()
    }

    /// Retrieve a list of the third-party caveats for the macaroon
    pub fn third_party_caveats(&self) -> Vec<ThirdPartyCaveat> {
        self.caveats
            .iter()
            .filter(|c| c.get_type() == CaveatType::ThirdParty)
            .map(|c| c.as_third_party().unwrap().clone())
            .collect()
    }

    /// Validate the macaroon - used mainly for validating deserialized macaroons
    pub fn validate(self) -> Result<Self, MacaroonError> {
        if self.identifier.is_empty() {
            return Err(MacaroonError::BadMacaroon("No macaroon identifier"));
        }
        if self.signature.is_empty() {
            return Err(MacaroonError::BadMacaroon("No macaroon signature"));
        }

        Ok(self)
    }

    /// Generate a signature for the given macaroon
    pub fn generate_signature(&self, key: &[u8]) -> [u8; 32] {
        let signature: [u8; 32] = crypto::generate_signature(key, &self.identifier);
        self.caveats.iter().fold(signature, |sig, caveat| caveat.sign(&sig))
    }

    /// Verify the signature of the macaroon given the key
    pub fn verify_signature(&self, key: &[u8]) -> bool {
        let signature = self.generate_signature(key);
        signature == self.signature
    }

    /// Add a first-party caveat to the macaroon
    ///
    /// A first-party caveat is just a string predicate in some
    /// DSL which can be verified either by exact string match,
    /// or by using a function to parse the string and validate it
    /// (see Verifier for more info).
    pub fn add_first_party_caveat<'r>(&mut self, predicate: &'r str) {
        let caveat: caveat::FirstPartyCaveat = caveat::new_first_party(predicate);
        self.signature = caveat.sign(&self.signature);
        self.caveats.push(Box::new(caveat));
        debug!("Macaroon::add_first_party_caveat: {:?}", self);
    }

    /// Add a third-party caveat to the macaroon
    ///
    /// A third-party caveat is a caveat which must be verified by a third party
    /// using macaroons provided by them (referred to as "discharge macaroons").
    pub fn add_third_party_caveat(&mut self, location: &str, key: &[u8], id: &str) {
        let derived_key: [u8; 32] = crypto::generate_derived_key(key);
        let vid: Vec<u8> = crypto::encrypt(self.signature, &derived_key);
        let caveat: caveat::ThirdPartyCaveat = caveat::new_third_party(id, vid, location);
        self.signature = caveat.sign(&self.signature);
        self.caveats.push(Box::new(caveat));
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
        discharge.signature = crypto::hmac2(&[0; 32], &self.signature, &discharge.signature);
        debug!("Macaroon::bind: original: {:?}, discharge: {:?}",
               self,
               discharge);
    }

    /// Verify a macaroon
    ///
    /// Verifies that the bearer of the macaroon is authorized to perform the actions requested.
    /// Takes the original key used to create the macaroon, and a verifier which must contain
    /// all criteria used to satisfy the caveats in the macaroon, plus any discharge macaroons
    /// to satisfy any third-party caveats, which must be already bound to this macaroon.
    ///
    /// Returns `Ok(true)` if authorized, `Ok(false)` if not, and `MacaroonError` if there was an error
    /// verifying the macaroon.
    pub fn verify(&self, key: &[u8], verifier: &mut Verifier) -> Result<bool, MacaroonError> {
        if !self.verify_signature(key) {
            info!("Macaroon::verify: Macaroon {:?} failed signature verification",
                  self);
            return Ok(false);
        }
        verifier.reset();
        verifier.set_signature(crypto::generate_signature(key, &self.identifier));
        self.verify_caveats(verifier)
    }

    fn verify_caveats(&self, verifier: &mut Verifier) -> Result<bool, MacaroonError> {
        for caveat in &self.caveats {
            match caveat.verify(self, verifier) {
                Ok(true) => (),
                Ok(false) => return Ok(false),
                Err(error) => return Err(error),
            }
        }

        Ok(true)
    }

    fn verify_as_discharge(&self,
                           verifier: &mut Verifier,
                           root_macaroon: &Macaroon,
                           key: &[u8])
                           -> Result<bool, MacaroonError> {
        let signature = self.generate_signature(key);
        if !self.verify_discharge_signature(root_macaroon, &signature) {
            info!("Macaroon::verify_as_discharge: Signature of discharge macaroon {:?} failed \
                   verification",
                  self);
            return Ok(false);
        }
        self.verify_caveats(verifier)
    }

    fn verify_discharge_signature(&self, root_macaroon: &Macaroon, signature: &[u8; 32]) -> bool {
        let discharge_signature = crypto::hmac2(&[0; 32], &root_macaroon.signature, signature);
        debug!("Macaroon::verify_discharge_signature: self.signature = {:?}, discharge signature \
                = {:?}",
               self.signature,
               discharge_signature);
        self.signature == discharge_signature
    }

    /// Serialize the macaroon using the serialization format provided
    pub fn serialize(&self, format: serialization::Format) -> Result<Vec<u8>, MacaroonError> {
        match format {
            serialization::Format::V1 => serialization::v1::serialize_v1(self),
            serialization::Format::V2 => serialization::v2::serialize_v2(self),
            serialization::Format::V2J => serialization::v2j::serialize_v2j(self),
        }
    }

    /// Deserialize a macaroon
    pub fn deserialize(data: &[u8]) -> Result<Macaroon, MacaroonError> {
        let macaroon: Macaroon = match data[0] as char {
            '{' => serialization::v2j::deserialize_v2j(data)?,
            '\x02' => serialization::v2::deserialize_v2(data)?,
            'a'..='z' | 'A'..='Z' | '0'..='9' | '+' | '-' | '/' | '_' => {
                serialization::v1::deserialize_v1(data)?
            }
            _ => return Err(MacaroonError::UnknownSerialization),
        };
        macaroon.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::Macaroon;
    use error::MacaroonError;
    use caveat::Caveat;

    #[test]
    fn create_macaroon() {
        let signature = [142, 227, 10, 28, 80, 115, 181, 176, 112, 56, 115, 95, 128, 156, 39, 20,
                         135, 17, 207, 204, 2, 80, 90, 249, 68, 40, 100, 60, 47, 220, 5, 224];
        let key: &[u8; 32] = b"this is a super duper secret key";
        let macaroon_res = Macaroon::create("location", key, "identifier");
        assert!(macaroon_res.is_ok());
        let macaroon = macaroon_res.unwrap();
        assert!(macaroon.location.is_some());
        assert_eq!("location", macaroon.location.unwrap());
        assert_eq!("identifier", macaroon.identifier);
        assert_eq!(signature.to_vec(), macaroon.signature);
        assert_eq!(0, macaroon.caveats.len());
    }

    #[test]
    fn create_invalid_macaroon() {
        let key: &[u8; 32] = b"this is a super duper secret key";
        let macaroon_res: Result<Macaroon, MacaroonError> = Macaroon::create("location", key, "");
        assert!(macaroon_res.is_err());
    }

    #[test]
    fn create_macaroon_with_first_party_caveat() {
        let signature = [132, 133, 51, 243, 147, 201, 178, 7, 193, 179, 36, 128, 4, 228, 17, 84,
                         166, 81, 30, 152, 15, 51, 47, 33, 196, 60, 20, 109, 163, 151, 133, 18];
        let key: &[u8; 32] = b"this is a super duper secret key";
        let mut macaroon = Macaroon::create("location", key, "identifier").unwrap();
        macaroon.add_first_party_caveat("predicate");
        assert_eq!(1, macaroon.caveats.len());
        let ref caveat = macaroon.caveats[0];
        assert_eq!("predicate", caveat.as_first_party().unwrap().predicate());
        assert_eq!(signature.to_vec(), macaroon.signature);
        assert_eq!(*caveat.as_first_party().unwrap(),
                   macaroon.first_party_caveats()[0]);
    }

    #[test]
    fn create_macaroon_with_third_party_caveat() {
        let key: &[u8; 32] = b"this is a super duper secret key";
        let mut macaroon = Macaroon::create("location", key, "identifier").unwrap();
        let location = "https://auth.mybank.com";
        let cav_key = b"My key";
        let id = "My Caveat";
        macaroon.add_third_party_caveat(location, cav_key, id);
        assert_eq!(1, macaroon.caveats.len());
        let caveat = macaroon.caveats[0].as_third_party().unwrap();
        assert_eq!(location, caveat.location());
        assert_eq!(id, caveat.id());
        assert_eq!(*caveat.as_third_party().unwrap(),
                   macaroon.third_party_caveats()[0]);
    }
}
