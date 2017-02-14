//! Implementation of [Macaroons](http://research.google.com/pubs/pub41892.html) for Rust, which are
//! flexible authorization tokens for distributed systems. They are similar to cookies, but allow for
//! more narrowly-focused authorization based on contextual caveats. For more information, see
//! [here](https://raw.githubusercontent.com/rescrv/libmacaroons/master/README).
//!
//! I've tried to keep the interface similar to that of [libmacaroons](https://github.com/rescrv/libmacaroons),
//! which is the reference implementation for macaroons.
//!
//! # Example
//! ```
//! use libmacaroon_rs::macaroon::Macaroon;
//! use libmacaroon_rs::verifier::Verifier;
//!
//! libmacaroon_rs::initialize().unwrap(); // Force panic if initialization fails
//!
//! // First-party caveat
//! let mut macaroon = Macaroon::create("location", b"key", "id").unwrap();
//! macaroon.add_first_party_caveat("account = 12345678");
//!
//! // Now we verify the caveat
//! let mut verifier = Verifier::new();
//! verifier.satisfy_exact("account = 12345678");
//! match verifier.verify(&macaroon, b"key", &vec![]) {
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
//! let mut discharge = Macaroon::create("http://auth.mybank/",
//!                                      b"different key",
//!                                      "caveat id").unwrap();
//! discharge.add_first_party_caveat("account = 12345678");
//!
//! // Once we receive the discharge macaroons, we bind them to the original macaroon
//! macaroon.prepare_for_request(&mut discharge);
//!
//! // Then we can verify using the same verifier (which will verify both the existing
//! // first-party caveat and the third party one)
//! match verifier.verify(&macaroon, b"key", &vec![discharge]) {
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

pub mod caveat;
pub mod crypto;
pub mod error;
pub mod macaroon;
pub mod serialization;
pub mod verifier;

use error::MacaroonError;

/// Initializes the cryptographic libraries. Although you can use libmacaroon-rs without
/// calling this, the underlying random-number generator is not guaranteed to be thread-safe
/// if you don't.
pub fn initialize() -> Result<(), MacaroonError> {
    match sodiumoxide::init() {
        true => Ok(()),
        false => Err(MacaroonError::InitializationError),
    }
}