use crypto;
use error::MacaroonError;
use std::str;
use serialization;
use caveat::{self, Caveat};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Macaroon {
    pub location: Option<String>,
    pub identifier: String,
    pub signature: Vec<u8>,
    pub caveats: Vec<Box<Caveat>>,
}

impl Macaroon {
    pub fn create(location: &'static str,
                  key: &[u8; 32],
                  identifier: &'static str)
                  -> Result<Macaroon, MacaroonError> {
        let derived_key = crypto::generate_derived_key(&key)?;

        let macaroon: Macaroon = Macaroon {
            location: Some(String::from(location)),
            identifier: String::from(identifier),
            signature: crypto::hmac(&derived_key, identifier.as_bytes()).to_vec(),
            caveats: Vec::new(),
        };
        macaroon.validate()
    }

    pub fn validate(self) -> Result<Self, MacaroonError> {
        if self.identifier.is_empty() {
            return Err(MacaroonError::BadMacaroon("No macaroon identifier"));
        }
        if self.signature.is_empty() {
            return Err(MacaroonError::BadMacaroon("No macaroon signature"));
        }

        Ok(self)
    }

    #[allow(unused_variables)]
    pub fn verify(&self, verifier: &Verifier) -> Result<bool, MacaroonError> {
        Ok(true)
    }

    pub fn add_first_party_caveat(&mut self, predicate: &'static str) -> Result<(), MacaroonError> {
        self.signature = try!(crypto::hmac_vec(&self.signature, predicate.as_bytes())).to_vec();
        self.caveats.push(box caveat::new_first_party(predicate));
        Ok(())
    }

    pub fn add_third_party_caveat(&mut self,
                                  location: &str,
                                  key: &[u8; 32],
                                  id: &str)
                                  -> Result<(), MacaroonError> {
        let derived_key: [u8; 32] = crypto::generate_derived_key(key)?;
        let vid: Vec<u8> = crypto::encrypt(self.signature.as_slice(), derived_key);
        let signature = crypto::hmac2(&self.signature, &vid, id.as_bytes())?.to_vec();
        self.caveats.push(box caveat::new_third_party(id, vid, location));
        self.signature = signature;
        Ok(())
    }

    pub fn serialize(&self, format: serialization::Format) -> Result<Vec<u8>, MacaroonError> {
        let result = match format {
            serialization::Format::V1 => serialization::v1::serialize_v1(self),
            serialization::Format::V2 => serialization::v2::serialize_v2(self),
            serialization::Format::V2J => serialization::v2j::serialize_v2j(self),
        };
        println!("{:?}", result);
        result
    }

    pub fn deserialize(data: &Vec<u8>) -> Result<Macaroon, MacaroonError> {
        let macaroon: Macaroon = match data[0] as char {
            '{' => serialization::v2j::deserialize_v2j(data)?,
            '\x02' => serialization::v2::deserialize_v2(data)?,
            'a'...'z' | 'A'...'Z' | '0'...'9' | '+' | '-' | '/' | '_' => {
                serialization::v1::deserialize_v1(data)?
            }
            _ => return Err(MacaroonError::UnknownSerialization),
        };
        macaroon.validate()
    }
}

pub type VerifierCallback = fn(&Caveat) -> Result<bool, MacaroonError>;

#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::Macaroon;
    use error::MacaroonError;

    #[test]
    fn create_macaroon() {
        let signature = [142, 227, 10, 28, 80, 115, 181, 176, 112, 56, 115, 95, 128, 156, 39, 20,
                         135, 17, 207, 204, 2, 80, 90, 249, 68, 40, 100, 60, 47, 220, 5, 224];
        let key: &[u8; 32] = b"this is a super duper secret key";
        let macaroon_res = Macaroon::create("location", key, "identifier");
        assert!(macaroon_res.is_ok());
        let macaroon = macaroon_res.unwrap();
        assert!(macaroon.location.is_some());
        assert_eq!("location", macaroon.location.unwrap());
        assert_eq!("identifier", macaroon.identifier);
        assert_eq!(signature.to_vec(), macaroon.signature);
        assert_eq!(0, macaroon.caveats.len());
    }

    #[test]
    fn create_invalid_macaroon() {
        let key: &[u8; 32] = b"this is a super duper secret key";
        let macaroon_res: Result<Macaroon, MacaroonError> = Macaroon::create("location", key, "");
        assert!(macaroon_res.is_err());
    }

    #[test]
    fn create_macaroon_with_first_party_caveat() {
        let signature = [132, 133, 51, 243, 147, 201, 178, 7, 193, 179, 36, 128, 4, 228, 17, 84,
                         166, 81, 30, 152, 15, 51, 47, 33, 196, 60, 20, 109, 163, 151, 133, 18];
        let key: &[u8; 32] = b"this is a super duper secret key";
        let mut macaroon = Macaroon::create("location", key, "identifier").unwrap();
        let cav_result = macaroon.add_first_party_caveat("predicate");
        assert!(cav_result.is_ok());
        assert_eq!(1, macaroon.caveats.len());
        let ref caveat = macaroon.caveats[0];
        assert_eq!("predicate", caveat.get_predicate().unwrap());
        assert_eq!(None, caveat.get_verifier_id());
        assert_eq!(None, caveat.get_location());
        assert_eq!(signature.to_vec(), macaroon.signature);
    }
}