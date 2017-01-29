use error::MacaroonError;
use sodiumoxide::crypto::auth::hmacsha256::{self, Tag, Key};
use std::str;
use super::serialization::*;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Caveat {
    pub id: String,
    pub verifier_id: Option<String>,
    pub location: Option<String>,
}

impl Caveat {
    pub fn new(id: String,
               verifier_id: Option<String>,
               location: Option<String>)
               -> Caveat {
        Caveat {
            id: id,
            verifier_id: verifier_id,
            location: location,
        }
    }
}

pub enum Format {
    V1,
    V2,
    V2J,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Macaroon {
    pub location: String,
    pub identifier: String,
    pub signature: Vec<u8>,
    pub caveats: Vec<Caveat>,
}

const KEY_GENERATOR: &'static [u8; 32] = b"macaroons-key-generator\0\0\0\0\0\0\0\0\0";

impl Macaroon {
    pub fn create(location: &'static str,
                  key: [u8; 32],
                  identifier: &'static str)
                  -> Result<Macaroon, MacaroonError> {
        let temp_key = try!(hmac_vec(&KEY_GENERATOR.to_vec(), &key));
        Ok(Macaroon {
            location: String::from(location),
            identifier: String::from(identifier),
            signature: hmac(&temp_key, identifier.as_bytes()).to_vec(),
            caveats: Vec::new(),
        })
    }

    #[allow(unused_variables)]
    pub fn verify(&self, verifier: &Verifier) -> Result<bool, MacaroonError> {
        Ok(true)
    }

    #[allow(unused_variables)]
    pub fn add_first_party_caveat(&mut self, predicate: &'static str) -> Result<(), MacaroonError> {
        self.signature = try!(hmac_vec(&self.signature, predicate.as_bytes())).to_vec();
        self.caveats.push(Caveat::new(String::from(predicate), None, None));
        Ok(())
    }

    #[allow(unused_variables)]
    pub fn serialize(&self, format: Format) -> Result<String, MacaroonError> {
        match format {
            Format::V1 => serialize_v1(self),
            Format::V2 => serialize_v2(self),
            Format::V2J => serialize_v2j(self),
        }
    }

    #[allow(unused_variables)]
    pub fn deserialize(data: &str) -> Result<Macaroon, MacaroonError> {
        match data.as_bytes()[0] as char {
            '}' => deserialize_v2j(data),
            '\x02' => deserialize_v2(data),
            'a'...'z' | 'A'...'Z' | '0'...'9' | '+' | '-' | '/' | '_' => deserialize_v1(data),
            _ => Err(MacaroonError::UnknownSerialization),
        }
    }
}

pub type VerifierCallback = fn(&Caveat) -> Result<bool, MacaroonError>;

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
}

fn hmac_vec<'r>(key: &'r Vec<u8>, text: &'r [u8]) -> Result<[u8; 32], MacaroonError> {
    if key.len() != 32 {
        return Err(MacaroonError::KeyError("Wrong key length"));
    }
    let mut key_static: [u8; 32] = [0; 32];
    for i in 0..key.len() {
        key_static[i] = key[i];
    }
    Ok(hmac(&key_static, text))
}

fn hmac<'r>(key: &'r [u8; 32], text: &'r [u8]) -> [u8; 32] {
    let Tag(result_bytes) = hmacsha256::authenticate(text, &Key(*key));
    result_bytes
}

#[cfg(test)]
mod tests {
    use super::Macaroon;

    #[test]
    fn create_macaroon() {
        let signature = [142, 227, 10, 28, 80, 115, 181, 176, 112, 56, 115, 95, 128, 156, 39, 20,
                         135, 17, 207, 204, 2, 80, 90, 249, 68, 40, 100, 60, 47, 220, 5, 224];
        let key: &[u8; 32] = b"this is a super duper secret key";
        let macaroon_res = Macaroon::create("location", *key, "identifier");
        assert!(macaroon_res.is_ok());
        let macaroon = macaroon_res.unwrap();
        assert_eq!("location", macaroon.location);
        assert_eq!("identifier", macaroon.identifier);
        assert_eq!(signature.to_vec(), macaroon.signature);
        assert_eq!(0, macaroon.caveats.len());
    }

    #[test]
    fn create_macaroon_with_first_party_caveat() {
        let signature = [132, 133, 51, 243, 147, 201, 178, 7, 193, 179, 36, 128, 4, 228, 17, 84,
                         166, 81, 30, 152, 15, 51, 47, 33, 196, 60, 20, 109, 163, 151, 133, 18];
        let key: &[u8; 32] = b"this is a super duper secret key";
        let mut macaroon = Macaroon::create("location", *key, "identifier").unwrap();
        let cav_result = macaroon.add_first_party_caveat("predicate");
        assert!(cav_result.is_ok());
        assert_eq!(1, macaroon.caveats.len());
        let ref caveat = macaroon.caveats[0];
        assert_eq!("predicate", caveat.id);
        assert_eq!(None, caveat.verifier_id);
        assert_eq!(None, caveat.location);
        assert_eq!(signature.to_vec(), macaroon.signature);
    }
}