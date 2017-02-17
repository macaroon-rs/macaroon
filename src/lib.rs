//! Implementation of [Macaroons](http://research.google.com/pubs/pub41892.html) for Rust, which are
//! flexible authorization tokens for distributed systems. They are similar to cookies, but allow for
//! more narrowly-focused authorization based on contextual caveats. For more information, see
//! [here](https://raw.githubusercontent.com/rescrv/libmacaroons/master/README).
//!
//! # Example
//! ```
//! use libmacaroon::{Macaroon, Verifier};
//!
//! // Initialize to make crypto primitives thread-safe
//! libmacaroon::initialize().unwrap(); // Force panic if initialization fails
//!
//! // First-party caveat
//! let mut macaroon = match Macaroon::create("location", b"key", "id") {
//!     Ok(macaroon) => macaroon,
//!     Err(error) => panic!("Error creating macaroon: {:?}", error),
//! };
//! macaroon.add_first_party_caveat("account = 12345678");
//!
//! // Now we verify the caveat
//! let mut verifier = Verifier::new();
//! verifier.satisfy_exact("account = 12345678");
//! match macaroon.verify(b"key", &mut verifier) {
//!     Ok(true) => println!("Macaroon verified!"),
//!     Ok(false) => println!("Macaroon verification failed"),
//!     Err(error) => println!("Error validating macaroon: {:?}", error),
//! }
//!
//! // Add a third-party caveat
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
//! discharge.add_first_party_caveat("account = 12345678");
//!
//! // Once we receive the discharge macaroons, we bind them to the original macaroon
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

#![feature(proc_macro)]
#![feature(try_from)]
#![feature(box_syntax, box_patterns)]

extern crate rustc_serialize as serialize;
extern crate sodiumoxide;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

mod caveat;
mod crypto;
pub mod error;
mod serialization;
pub mod verifier;

pub use verifier::Verifier;
pub use error::MacaroonError;

use caveat::Caveat;

/// Initializes the cryptographic libraries. Although you can use libmacaroon-rs without
/// calling this, the underlying random-number generator is not guaranteed to be thread-safe
/// if you don't.
pub fn initialize() -> Result<(), MacaroonError> {
    match sodiumoxide::init() {
        true => Ok(()),
        false => Err(MacaroonError::InitializationError),
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Macaroon {
    identifier: String,
    location: Option<String>,
    signature: [u8; 32],
    caveats: Vec<Box<Caveat>>,
}

impl Macaroon {
    pub fn create(location: &'static str,
                  key: &[u8],
                  identifier: &'static str)
                  -> Result<Macaroon, MacaroonError> {
        let macaroon_key = crypto::generate_derived_key(key);

        let macaroon: Macaroon = Macaroon {
            location: Some(String::from(location)),
            identifier: String::from(identifier),
            signature: crypto::generate_signature(&macaroon_key, identifier),
            caveats: Vec::new(),
        };
        macaroon.validate()
    }

    pub fn get_identifier(&self) -> &String {
        &self.identifier
    }

    pub fn get_location(&self) -> Option<String> {
        self.location.clone()
    }

    pub fn get_signature(&self) -> &[u8; 32] {
        &self.signature
    }

    fn get_caveats(&self) -> &Vec<Box<Caveat>> {
        &self.caveats
    }

    pub fn validate(self) -> Result<Self, MacaroonError> {
        if self.identifier.is_empty() {
            return Err(MacaroonError::BadMacaroon("No macaroon identifier"));
        }
        if self.signature.is_empty() {
            return Err(MacaroonError::BadMacaroon("No macaroon signature"));
        }

        Ok(self)
    }

    pub fn generate_signature(&self, key: &[u8]) -> [u8; 32] {
        let mut signature: [u8; 32] = crypto::generate_signature(key, &self.identifier);
        // TODO: Do this with a fold?
        for ref caveat in &self.caveats {
            signature = caveat.sign(&signature);
        }
        signature
    }

    pub fn verify_signature(&self, key: &[u8]) -> bool {
        let signature = self.generate_signature(key);
        signature == self.signature
    }

    pub fn add_first_party_caveat(&mut self, predicate: &'static str) {
        let caveat: caveat::FirstPartyCaveat = caveat::new_first_party(predicate);
        self.signature = caveat.sign(&self.signature);
        self.caveats.push(box caveat);
    }

    pub fn add_third_party_caveat(&mut self, location: &str, key: &[u8], id: &str) {
        let derived_key: [u8; 32] = crypto::generate_derived_key(key);
        let vid: Vec<u8> = crypto::encrypt(self.signature, &derived_key);
        let caveat: caveat::ThirdPartyCaveat = caveat::new_third_party(id, vid, location);
        self.signature = caveat.sign(&self.signature);
        self.caveats.push(box caveat);
    }

    pub fn bind(&self, discharge: &mut Macaroon) {
        discharge.signature = crypto::hmac2(&[0; 32], &self.signature, &discharge.signature);
    }

    pub fn verify(&self, key: &[u8], verifier: &mut Verifier) -> Result<bool, MacaroonError> {
        if !self.verify_signature(key) {
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
            return Ok(false);
        }
        self.verify_caveats(verifier)
    }

    fn verify_discharge_signature(&self, root_macaroon: &Macaroon, signature: &[u8; 32]) -> bool {
        let discharge_signature = crypto::hmac2(&[0; 32], &root_macaroon.signature, signature);
        self.signature == discharge_signature
    }

    pub fn serialize(&self, format: serialization::Format) -> Result<Vec<u8>, MacaroonError> {
        match format {
            serialization::Format::V1 => serialization::v1::serialize_v1(self),
            serialization::Format::V2 => serialization::v2::serialize_v2(self),
            serialization::Format::V2J => serialization::v2j::serialize_v2j(self),
        }
    }

    pub fn deserialize(data: &Vec<u8>) -> Result<Macaroon, MacaroonError> {
        let macaroon: Macaroon = match data[0] as char {
            '{' => serialization::v2j::deserialize_v2j(data)?,
            '\x02' => serialization::v2::deserialize_v2(data)?,
            'a'...'z' | 'A'...'Z' | '0'...'9' | '+' | '-' | '/' | '_' => {
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
        assert_eq!("predicate",
                   caveat.as_first_party().unwrap().get_predicate());
        assert_eq!(signature.to_vec(), macaroon.signature);
    }
}