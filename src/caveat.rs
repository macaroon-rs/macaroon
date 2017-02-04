use error::MacaroonError;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Caveat {
    pub id: String,
    pub verifier_id: Option<Vec<u8>>,
    pub location: Option<String>,
}

impl Caveat {
    pub fn new_first_party(predicate: &str) -> Caveat {
        Caveat {
            id: String::from(predicate),
            verifier_id: None,
            location: None,
        }
    }

    pub fn new_third_party(id: &str, verifier_id: Vec<u8>, location: &str) -> Caveat {
        Caveat {
            id: String::from(id),
            verifier_id: Some(verifier_id),
            location: Some(String::from(location)),
        }
    }

    pub fn verify(&self) -> Result<bool, MacaroonError> {
        Ok(true)
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

    pub fn build(self) -> Result<Caveat, MacaroonError> {
        if self.id.is_none() {
            return Err(MacaroonError::BadMacaroon("No identifier found"));
        }
        if self.verifier_id.is_none() && self.location.is_none() {
            return Ok(Caveat::new_first_party(&self.id.unwrap()));
        }
        if self.verifier_id.is_some() && self.location.is_some() {
            return Ok(Caveat::new_third_party(&self.id.unwrap(),
                                              self.verifier_id.unwrap(),
                                              &self.location.unwrap()));
        }
        if self.verifier_id.is_none() {
            return Err(MacaroonError::BadMacaroon("Location but no verifier ID found"));
        }
        Err(MacaroonError::BadMacaroon("Verifier ID but no location found"))
    }
}