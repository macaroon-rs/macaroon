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

pub fn initialize() -> Result<(), MacaroonError> {
    match sodiumoxide::init() {
        true => Ok(()),
        false => Err(MacaroonError::InitializationError),
    }
}