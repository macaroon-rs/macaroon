use crypto;
use error::MacaroonError;
use macaroon::Macaroon;
use verifier::Verifier;
use std::fmt::Debug;

#[derive(PartialEq)]
pub enum CaveatType {
    FirstParty,
    ThirdParty,
}

pub trait Caveat: Debug {
    fn verify(&self,
              macaroon: &Macaroon,
              verifier: &Verifier,
              signature: &mut [u8; 32],
              discharge_macaroons: &Vec<Macaroon>,
              id_chain: &mut Vec<String>)
              -> Result<bool, MacaroonError>;

    fn sign(&self, key: &[u8; 32]) -> [u8; 32];
    fn get_type(&self) -> CaveatType;
    fn as_first_party(&self) -> Result<&FirstPartyCaveat, ()>;
    fn as_third_party(&self) -> Result<&ThirdPartyCaveat, ()>;

    // Required for Clone below
    fn clone_box(&self) -> Box<Caveat>;
}

impl Clone for Box<Caveat> {
    fn clone(&self) -> Box<Caveat> {
        self.clone_box()
    }
}

impl PartialEq for Caveat {
    fn eq(&self, other: &Caveat) -> bool {
        if self.get_type() != other.get_type() {
            return false;
        }

        match self.get_type() {
            CaveatType::FirstParty => {
                let me = self.as_first_party();
                let you = other.as_first_party();
                return me == you;
            }
            CaveatType::ThirdParty => {
                let me = self.as_third_party();
                let you = other.as_third_party();
                return me == you;
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct FirstPartyCaveat {
    predicate: String,
}

impl FirstPartyCaveat {
    pub fn new(predicate: &str) -> FirstPartyCaveat {
        FirstPartyCaveat { predicate: String::from(predicate) }
    }

    pub fn get_predicate(&self) -> String {
        self.predicate.clone()
    }
}

impl Caveat for FirstPartyCaveat {
    fn verify(&self,
              _: &Macaroon,
              verifier: &Verifier,
              signature: &mut [u8; 32],
              _: &Vec<Macaroon>,
              _: &mut Vec<String>)
              -> Result<bool, MacaroonError> {
        let result = Ok(verifier.verify_predicate(&self.predicate));
        *signature = self.sign(signature);
        result
    }

    fn sign(&self, key: &[u8; 32]) -> [u8; 32] {
        crypto::hmac(key, self.predicate.as_bytes())
    }

    fn get_type(&self) -> CaveatType {
        CaveatType::FirstParty
    }

    fn as_first_party(&self) -> Result<&FirstPartyCaveat, ()> {
        Ok(self)
    }

    fn as_third_party(&self) -> Result<&ThirdPartyCaveat, ()> {
        Err(())
    }

    fn clone_box(&self) -> Box<Caveat> {
        box self.clone()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ThirdPartyCaveat {
    id: String,
    verifier_id: Vec<u8>,
    location: String,
}

impl ThirdPartyCaveat {
    pub fn get_id(&self) -> String {
        self.id.clone()
    }

    pub fn get_verifier_id(&self) -> Vec<u8> {
        self.verifier_id.clone()
    }

    pub fn get_location(&self) -> String {
        self.location.clone()
    }
}

impl Caveat for ThirdPartyCaveat {
    fn verify(&self,
              macaroon: &Macaroon,
              verifier: &Verifier,
              signature: &mut [u8; 32],
              discharge_macaroons: &Vec<Macaroon>,
              id_chain: &mut Vec<String>)
              -> Result<bool, MacaroonError> {
        let result =
            verifier.verify_caveat(&self, macaroon, signature, discharge_macaroons, id_chain);
        *signature = self.sign(&signature);
        result
    }

    fn sign(&self, key: &[u8; 32]) -> [u8; 32] {
        crypto::hmac2(key, &self.verifier_id, self.id.as_bytes())
    }

    fn get_type(&self) -> CaveatType {
        CaveatType::ThirdParty
    }

    fn as_first_party(&self) -> Result<&FirstPartyCaveat, ()> {
        Err(())
    }

    fn as_third_party(&self) -> Result<&ThirdPartyCaveat, ()> {
        Ok(self)
    }

    fn clone_box(&self) -> Box<Caveat> {
        box self.clone()
    }
}

pub fn new_first_party(predicate: &str) -> FirstPartyCaveat {
    FirstPartyCaveat { predicate: String::from(predicate) }
}

pub fn new_third_party(id: &str, verifier_id: Vec<u8>, location: &str) -> ThirdPartyCaveat {
    ThirdPartyCaveat {
        id: String::from(id),
        verifier_id: verifier_id,
        location: String::from(location),
    }
}

#[derive(Default)]
pub struct CaveatBuilder {
    id: Option<String>,
    verifier_id: Option<Vec<u8>>,
    location: Option<String>,
}

impl CaveatBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add_id(&mut self, id: String) {
        self.id = Some(id);
    }

    pub fn has_id(&self) -> bool {
        self.id.is_some()
    }

    pub fn add_verifier_id(&mut self, vid: Vec<u8>) {
        self.verifier_id = Some(vid);
    }

    pub fn add_location(&mut self, location: String) {
        self.location = Some(location);
    }

    pub fn has_location(&self) -> bool {
        self.location.is_some()
    }

    pub fn build(self) -> Result<Box<Caveat>, MacaroonError> {
        if self.id.is_none() {
            return Err(MacaroonError::BadMacaroon("No identifier found"));
        }
        if self.verifier_id.is_none() && self.location.is_none() {
            return Ok(box new_first_party(&self.id.unwrap()));
        }
        if self.verifier_id.is_some() && self.location.is_some() {
            return Ok(box new_third_party(&self.id.unwrap(),
                                          self.verifier_id.unwrap(),
                                          &self.location.unwrap()));
        }
        if self.verifier_id.is_none() {
            return Err(MacaroonError::BadMacaroon("Location but no verifier ID found"));
        }
        Err(MacaroonError::BadMacaroon("Verifier ID but no location found"))
    }
}