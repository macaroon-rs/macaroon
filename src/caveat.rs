use crypto;
use error::MacaroonError;
use macaroon::Macaroon;
use verifier::Verifier;
use std::any::Any;
use std::fmt::Debug;

pub trait Caveat: Any + Debug {
    fn get_id(&self) -> Option<&str>;
    fn get_predicate(&self) -> Option<&str>;
    fn get_verifier_id(&self) -> Option<Vec<u8>>;
    fn get_location(&self) -> Option<&str>;
    fn verify(&self,
              verifier: &Verifier,
              discharge_macaroons: &Vec<Macaroon>,
              id_chain: &mut Vec<String>)
              -> bool;
    fn get_type(&self) -> &'static str;
    fn as_any(&self) -> &Any;
    fn sign(&self, key: &[u8; 32]) -> [u8; 32];

    // Required for Clone below
    fn clone_box(&self) -> Box<Caveat>;

    fn get_serialized_id(&self) -> Result<&str, MacaroonError> {
        match self.get_id() {
            Some(id) => Ok(id),
            None => {
                match self.get_predicate() {
                    Some(predicate) => Ok(predicate),
                    None => Err(MacaroonError::BadMacaroon("No id found")),
                }
            }
        }
    }
}

impl Clone for Box<Caveat> {
    fn clone(&self) -> Box<Caveat> {
        self.clone_box()
    }
}

impl PartialEq for Caveat {
    fn eq(&self, other: &Caveat) -> bool {
        let me = self.as_any();
        let you = other.as_any();
        if me.is::<FirstPartyCaveat>() && you.is::<FirstPartyCaveat>() {
            self.get_predicate() == other.get_predicate()
        } else if me.is::<ThirdPartyCaveat>() && you.is::<ThirdPartyCaveat>() {
            self.get_id() == other.get_id() && self.get_location() == other.get_location() &&
            self.get_verifier_id() == other.get_verifier_id()
        } else {
            false
        }
    }
}

#[derive(Clone, Debug)]
pub struct FirstPartyCaveat {
    pub predicate: String,
}

impl Caveat for FirstPartyCaveat {
    fn get_id(&self) -> Option<&str> {
        None
    }

    fn get_predicate(&self) -> Option<&str> {
        Some(&self.predicate)
    }

    fn get_verifier_id(&self) -> Option<Vec<u8>> {
        None
    }

    fn get_location(&self) -> Option<&str> {
        None
    }

    fn get_type(&self) -> &'static str {
        "FirstPartyCaveat"
    }

    fn clone_box(&self) -> Box<Caveat> {
        box self.clone()
    }

    fn verify(&self, verifier: &Verifier, _: &Vec<Macaroon>, _: &mut Vec<String>) -> bool {
        verifier.verify_predicate(&self.predicate)
    }

    fn as_any(&self) -> &Any {
        self
    }

    fn sign(&self, key: &[u8; 32]) -> [u8; 32] {
        crypto::hmac(key, self.predicate.as_bytes())
    }
}

#[derive(Clone, Debug)]
pub struct ThirdPartyCaveat {
    pub id: String,
    pub verifier_id: Vec<u8>,
    pub location: String,
}

impl Caveat for ThirdPartyCaveat {
    fn get_id(&self) -> Option<&str> {
        Some(&self.id)
    }

    fn get_predicate(&self) -> Option<&str> {
        None
    }

    fn get_verifier_id(&self) -> Option<Vec<u8>> {
        Some(self.verifier_id.clone())
    }

    fn get_location(&self) -> Option<&str> {
        Some(&self.location)
    }

    fn clone_box(&self) -> Box<Caveat> {
        box self.clone()
    }

    fn get_type(&self) -> &'static str {
        "ThirdPartyCaveat"
    }

    fn verify(&self,
              verifier: &Verifier,
              discharge_macaroons: &Vec<Macaroon>,
              id_chain: &mut Vec<String>)
              -> bool {
        verifier.verify_caveat(&self.id, discharge_macaroons, id_chain)
    }

    fn as_any(&self) -> &Any {
        self
    }

    fn sign(&self, key: &[u8; 32]) -> [u8; 32] {
        crypto::hmac2(key, &self.verifier_id, self.id.as_bytes())
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