use caveat::Caveat;
use error::MacaroonError;
use macaroon::Macaroon;

pub type VerifierCallback = fn(&Caveat) -> Result<bool, MacaroonError>;

#[allow(dead_code)]
pub struct Verifier {
    pub predicates: Vec<String>,
    pub callbacks: Vec<VerifierCallback>,
}

impl Verifier {
    pub fn new() -> Verifier {
        Verifier {
            predicates: Vec::new(),
            callbacks: Vec::new(),
        }
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