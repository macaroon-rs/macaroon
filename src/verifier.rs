use error::MacaroonError;
use macaroon::Macaroon;

pub type VerifierCallback = fn(&str) -> bool;

pub struct Verifier {
    predicates: Vec<String>,
    callbacks: Vec<VerifierCallback>,
}

impl Verifier {
    pub fn new() -> Verifier {
        Verifier {
            predicates: Vec::new(),
            callbacks: Vec::new(),
        }
    }

    pub fn satisfy_exact(&mut self, predicate: &str) {
        self.predicates.push(String::from(predicate));
    }

    pub fn satisfy_general(&mut self, callback: VerifierCallback) {
        self.callbacks.push(callback);
    }

    pub fn verify_predicate(&self, predicate: &str) -> bool {
        let mut count = self.predicates.iter().filter(|&p| p == predicate).count();
        if count > 0 {
            return true;
        }

        count = self.callbacks.iter().filter(|&callback| callback(predicate)).count();
        if count > 0 {
            return true;
        }

        false
    }

    pub fn verify(macaroon: &Macaroon,
                  key: &[u8; 32],
                  discharge_macaroons: Vec<Macaroon>)
                  -> Result<bool, MacaroonError> {
        if !macaroon.verify_signature(key) {
            return Ok(false);
        }
        for ref dm in discharge_macaroons {
            if !dm.verify_signature(key) {
                return Ok(false);
            }
        }
        unimplemented!()
    }
}