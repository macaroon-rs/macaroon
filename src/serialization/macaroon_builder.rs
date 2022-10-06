use crate::caveat::Caveat;
use crate::error::MacaroonError;
use crate::{ByteString, Macaroon, MacaroonKey, Result};

pub struct MacaroonBuilder {
    identifier: ByteString,
    location: Option<String>,
    signature: MacaroonKey,
    caveats: Vec<Caveat>,
}

impl MacaroonBuilder {
    pub fn new() -> MacaroonBuilder {
        MacaroonBuilder {
            identifier: Default::default(),
            location: None,
            signature: MacaroonKey::generate_random(),
            caveats: Default::default(),
        }
    }

    pub fn set_identifier(&mut self, identifier: ByteString) {
        self.identifier = identifier;
    }

    pub fn set_location(&mut self, location: &str) {
        self.location = Some((*location).to_string());
    }

    pub fn has_location(&self) -> bool {
        self.location.is_some()
    }

    pub fn set_signature(&mut self, signature: &[u8]) {
        self.signature.clone_from_slice(signature);
    }

    pub fn add_caveat(&mut self, caveat: Caveat) {
        self.caveats.push(caveat);
    }

    pub fn build(&self) -> Result<Macaroon> {
        if self.identifier.0.is_empty() {
            return Err(MacaroonError::IncompleteMacaroon("no identifier found"));
        }
        if self.signature.is_empty() {
            return Err(MacaroonError::IncompleteMacaroon("no signature found"));
        }

        Ok(Macaroon {
            identifier: self.identifier.clone(),
            location: self.location.clone(),
            signature: self.signature,
            caveats: self.caveats.clone(),
        })
    }
}
