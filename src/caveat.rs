use crypto;
use error::MacaroonError;
use std::fmt::Debug;
use verifier::Verifier;
use ByteString;
use Macaroon;

#[derive(Clone, Debug, PartialEq)]
pub enum Caveat {
    FirstParty(FirstParty),
    ThirdParty(ThirdParty),
}

#[derive(Clone, Debug, PartialEq)]
pub struct FirstParty {
    predicate: ByteString,
}

impl FirstParty {
    pub fn predicate(&self) -> ByteString {
        self.predicate.clone()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ThirdParty {
    id: ByteString,
    verifier_id: ByteString,
    location: String,
}

impl ThirdParty {
    pub fn id(&self) -> ByteString {
        self.id.clone()
    }
    pub fn verifier_id(&self) -> ByteString {
        self.verifier_id.clone()
    }
    pub fn location(&self) -> String {
        self.location.clone()
    }
}

impl Caveat {
    // TODO: See if we can just get rid of this function entirely and move all the logic to the verifier
    pub fn verify(
        &self,
        macaroon: &Macaroon,
        verifier: &mut Verifier,
    ) -> Result<bool, MacaroonError> {
        let result = verifier.verify(self, macaroon);
        if let Ok(false) = result {
            info!(
                "Caveat {:?} of macaroon {:?} failed verification",
                self, macaroon
            );
        }
        verifier.update_signature(|t| self.sign(t));
        result
    }

    pub fn sign(&self, key: &[u8; 32]) -> [u8; 32] {
        match self {
            Self::FirstParty(fp) => crypto::hmac(key, &fp.predicate),
            Self::ThirdParty(tp) => crypto::hmac2(key, &tp.verifier_id, &tp.id),
        }
    }
}

pub fn new_first_party(predicate: ByteString) -> Caveat {
    Caveat::FirstParty(FirstParty { predicate })
}

pub fn new_third_party(id: ByteString, verifier_id: ByteString, location: &str) -> Caveat {
    Caveat::ThirdParty(ThirdParty {
        id,
        verifier_id,
        location: String::from(location),
    })
}

#[derive(Default)]
pub struct CaveatBuilder {
    id: Option<ByteString>,
    verifier_id: Option<ByteString>,
    location: Option<String>,
}

impl CaveatBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add_id(&mut self, id: ByteString) {
        self.id = Some(id);
    }

    pub fn has_id(&self) -> bool {
        self.id.is_some()
    }

    pub fn add_verifier_id(&mut self, vid: ByteString) {
        self.verifier_id = Some(vid);
    }

    pub fn add_location(&mut self, location: String) {
        self.location = Some(location);
    }

    pub fn has_location(&self) -> bool {
        self.location.is_some()
    }

    pub fn build(self) -> Result<Caveat, MacaroonError> {
        if self.id.is_none() {
            return Err(MacaroonError::BadMacaroon("No identifier found"));
        }
        if self.verifier_id.is_none() && self.location.is_none() {
            return Ok(new_first_party(self.id.unwrap()));
        }
        if self.verifier_id.is_some() && self.location.is_some() {
            return Ok(new_third_party(
                self.id.unwrap(),
                self.verifier_id.unwrap(),
                &self.location.unwrap(),
            ));
        }
        if self.verifier_id.is_none() {
            return Err(MacaroonError::BadMacaroon(
                "Location but no verifier ID found",
            ));
        }
        Err(MacaroonError::BadMacaroon(
            "Verifier ID but no location found",
        ))
    }
}
