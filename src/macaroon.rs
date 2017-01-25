use error::Error;
use super::serialization::{serialize_v1, serialize_v2, serialize_v2j};
use sodiumoxide::crypto::auth::hmacsha256::{self, Tag, Key, State, TAGBYTES};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::utils;
use std::str;

#[derive(Debug)]
pub struct Caveat {
    id: &'static str,
    verifier_id: Option<&'static str>,
    location: Option<&'static str>,
}

impl Caveat {
    pub fn new(id: &'static str, verifier_id: Option<&'static str>, location: Option<&'static str>) -> Caveat {
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
    V2J
}

#[derive(Debug)]
pub struct Macaroon {
    location: &'static str,
    identifier: &'static str,
    signature: [u8;32],
    caveats: Vec<Caveat>,
}

const KEY_GENERATOR: &'static [u8; 32] = b"macaroons-key-generator\0\0\0\0\0\0\0\0\0";

impl Macaroon {
    pub fn create(location: &'static str,
                  key: [u8; 32],
                  identifier: &'static str)
                  -> Result<Macaroon, Error> {
        let temp_key = match str::from_utf8(&key) {
            Ok(key_str) => hmac(*KEY_GENERATOR, key_str),
            Err(error) => return Err(Error::NotUTF8(error)),
        };
        Ok(Macaroon {
            location: location,
            identifier: identifier,
            signature: hmac(temp_key, identifier),
            caveats: Vec::new(),
        })
    }

    #[allow(unused_variables)]
    pub fn verify(&self, verifier: &Verifier) -> Result<bool, Error> {
        Ok(true)
    }

    #[allow(unused_variables)]
    pub fn add_first_party_caveat(&mut self, predicate: &'static str) -> Result<(), Error> {
        self.signature = hmac(self.signature, predicate);
        self.caveats.push(Caveat::new(predicate, None, None));
        Ok(())
    }

    #[allow(unused_variables)]
    pub fn serialize(&self, format: Format) -> Result<Vec<u8>, Error> {
        match format {
            Format::V1 => serialize_v1(self),
            Format::V2 => serialize_v2(self),
            Format::V2J => serialize_v2j(self),
        }
    }

    #[allow(unused_variables)]
    pub fn deserialize(data: &[u8]) -> Result<Macaroon, Error> {
        unimplemented!()
    }
}

pub type VerifierCallback = fn(&Caveat) -> Result<bool, Error>;

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

fn hmac<'r>(key: [u8; 32], text: &'r str) -> [u8;32] {
    let Tag(result_bytes) = hmacsha256::authenticate(text.as_bytes(), &Key(key));
    result_bytes
}

#[cfg(test)]
mod tests {
    use super::Macaroon;

    #[test]
    fn create_macaroon() {
        let signature = [142, 227, 10, 28, 80, 115, 181, 176, 112, 56, 115, 95, 128, 156, 39, 20, 135, 17, 207, 204, 2, 80, 90, 249, 68, 40, 100, 60, 47, 220, 5, 224];
        let key: &[u8; 32] = b"this is a super duper secret key";
        let macaroon_res = Macaroon::create("location", *key, "identifier");
        assert!(macaroon_res.is_ok());
        let macaroon = macaroon_res.unwrap();
        assert_eq!("location", macaroon.location);
        assert_eq!("identifier", macaroon.identifier);
        assert_eq!(signature, macaroon.signature);
        assert_eq!(0, macaroon.caveats.len());
    }

    #[test]
    fn create_macaroon_with_first_party_caveat() {
        let signature = [132, 133, 51, 243, 147, 201, 178, 7, 193, 179, 36, 128, 4, 228, 17, 84, 166, 81, 30, 152, 15, 51, 47, 33, 196, 60, 20, 109, 163, 151, 133, 18];
        let key: &[u8; 32] = b"this is a super duper secret key";
        let mut macaroon = Macaroon::create("location", *key, "identifier").unwrap();
        let cav_result = macaroon.add_first_party_caveat("predicate");
        assert!(cav_result.is_ok());
        assert_eq!(1, macaroon.caveats.len());
        let ref caveat = macaroon.caveats[0];
        assert_eq!("predicate", caveat.id);
        assert_eq!(None, caveat.verifier_id);
        assert_eq!(None, caveat.location);
        assert_eq!(signature, macaroon.signature);
    }
}