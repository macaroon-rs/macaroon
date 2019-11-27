use crypto;
use error::MacaroonError;
use Macaroon;
use std::fmt::Debug;
use verifier::Verifier;

#[derive(PartialEq)]
pub enum CaveatType {
    FirstParty,
    ThirdParty,
}

pub trait Caveat: Debug {
    fn verify(&self, macaroon: &Macaroon, verifier: &mut Verifier) -> Result<bool, MacaroonError>;

    fn sign(&self, key: &[u8; 32]) -> [u8; 32];
    fn get_type(&self) -> CaveatType;
    fn as_first_party(&self) -> Result<&FirstPartyCaveat, ()>;
    fn as_third_party(&self) -> Result<&ThirdPartyCaveat, ()>;

    // Required for Clone below
    fn clone_box(&self) -> Box<dyn Caveat>;
}

impl Clone for Box<dyn Caveat> {
    fn clone(&self) -> Box<dyn Caveat> {
        self.clone_box()
    }
}

impl PartialEq for dyn Caveat {
    fn eq(&self, other: &dyn Caveat) -> bool {
        if self.get_type() != other.get_type() {
            return false;
        }

        match self.get_type() {
            CaveatType::FirstParty => {
                let me = self.as_first_party();
                let you = other.as_first_party();
                me == you
            }
            CaveatType::ThirdParty => {
                let me = self.as_third_party();
                let you = other.as_third_party();
                me == you
            }
        }
    }
}

/// Struct for a first-party caveat
#[derive(Clone, Debug, PartialEq)]
pub struct FirstPartyCaveat {
    predicate: String,
}

impl FirstPartyCaveat {
    /// Accessor for the predicate
    pub fn predicate(&self) -> String {
        self.predicate.clone()
    }
}

impl Caveat for FirstPartyCaveat {
    fn verify(&self, macaroon: &Macaroon, verifier: &mut Verifier) -> Result<bool, MacaroonError> {
        let result = Ok(verifier.verify_predicate(&self.predicate));
        if let Ok(false) = result {
            info!("FirstPartyCaveat::verify: Caveat {:?} of macaroon {:?} failed verification",
                  self,
                  macaroon);
        }
        verifier.update_signature(|t| self.sign(t));
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

    fn clone_box(&self) -> Box<dyn Caveat> {
        Box::new(self.clone())
    }
}

/// Struct for a third-party caveat
#[derive(Clone, Debug, PartialEq)]
pub struct ThirdPartyCaveat {
    id: String,
    verifier_id: Vec<u8>,
    location: String,
}

impl ThirdPartyCaveat {
    /// Accessor for the identifier
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// Accessor for the verifier ID
    pub fn verifier_id(&self) -> Vec<u8> {
        self.verifier_id.clone()
    }

    /// Accessor for the location
    pub fn location(&self) -> String {
        self.location.clone()
    }
}

impl Caveat for ThirdPartyCaveat {
    fn verify(&self, macaroon: &Macaroon, verifier: &mut Verifier) -> Result<bool, MacaroonError> {
        let result = verifier.verify_caveat(self, macaroon);
        if let Ok(false) = result {
            info!("ThirdPartyCaveat::verify: Caveat {:?} of macaroon {:?} failed verification",
                  self,
                  macaroon);
        }
        verifier.update_signature(|t| self.sign(t));
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

    fn clone_box(&self) -> Box<dyn Caveat> {
        Box::new(self.clone())
    }
}

pub fn new_first_party(predicate: &str) -> FirstPartyCaveat {
    FirstPartyCaveat { predicate: String::from(predicate) }
}

pub fn new_third_party(id: &str, verifier_id: Vec<u8>, location: &str) -> ThirdPartyCaveat {
    ThirdPartyCaveat {
        id: String::from(id),
        verifier_id,
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

    pub fn build(self) -> Result<Box<dyn Caveat>, MacaroonError> {
        if self.id.is_none() {
            return Err(MacaroonError::BadMacaroon("No identifier found"));
        }
        if self.verifier_id.is_none() && self.location.is_none() {
            return Ok(Box::new(new_first_party(&self.id.unwrap())));
        }
        if self.verifier_id.is_some() && self.location.is_some() {
            return Ok(Box::new(new_third_party(&self.id.unwrap(),
                                          self.verifier_id.unwrap(),
                                          &self.location.unwrap())));
        }
        if self.verifier_id.is_none() {
            return Err(MacaroonError::BadMacaroon("Location but no verifier ID found"));
        }
        Err(MacaroonError::BadMacaroon("Verifier ID but no location found"))
    }
}

#[cfg(test)]
mod tests {
    use super::{Caveat, new_first_party, new_third_party};

    #[test]
    fn test_caveat_partial_equals_first_party() {
        let a = new_first_party("user = alice");
        let b = new_first_party("user = alice");
        let c = new_first_party("user = bob");
        let box_a: Box<dyn Caveat> = Box::new(a);
        let box_b: Box<dyn Caveat> = Box::new(b);
        let box_c: Box<dyn Caveat> = Box::new(c);
        assert_eq!(*box_a, *box_b);
        assert!(*box_a != *box_c);
    }

    #[test]
    fn test_caveat_partial_equals_third_party() {
        let a = new_third_party("foo", b"bar".to_vec(), "foobar");
        let b = new_third_party("foo", b"bar".to_vec(), "foobar");
        let c = new_third_party("baz", b"bar".to_vec(), "foobar");
        let box_a: Box<dyn Caveat> = Box::new(a);
        let box_b: Box<dyn Caveat> = Box::new(b);
        let box_c: Box<dyn Caveat> = Box::new(c);
        assert_eq!(*box_a, *box_b);
        assert!(*box_a != *box_c);
    }
}
