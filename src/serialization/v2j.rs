use serde_json;
use serialize::base64::{STANDARD, ToBase64, FromBase64};
use std::convert::TryFrom;
use std::str;
use super::super::macaroon::{Caveat, Macaroon};
use super::super::error::MacaroonError;

#[derive(Debug, Default, Deserialize, Serialize)]
struct CaveatV2J {
    i: Option<String>,
    i64: Option<String>,
    l: Option<String>,
    l64: Option<String>,
    v: Option<Vec<u8>>,
    v64: Option<Vec<u8>>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct V2JSerialization {
    v: u8,
    i: Option<String>,
    i64: Option<String>,
    l: Option<String>,
    l64: Option<String>,
    c: Vec<CaveatV2J>,
    s: Option<Vec<u8>>,
    s64: Option<String>,
}

impl<'r> From<&'r Macaroon> for V2JSerialization {
    fn from(macaroon: &'r Macaroon) -> V2JSerialization {
        let mut serialized: V2JSerialization = V2JSerialization {
            v: 2,
            i: Some(macaroon.identifier.clone()),
            i64: None,
            l: macaroon.location.clone(),
            l64: None,
            c: Vec::new(),
            s: None,
            s64: Some(macaroon.signature.to_base64(STANDARD)),
        };
        for caveat in macaroon.caveats.clone() {
            let serialized_caveat: CaveatV2J = CaveatV2J {
                i: Some(caveat.id),
                i64: None,
                l: caveat.location,
                l64: None,
                v: caveat.verifier_id,
                v64: None,
            };
            serialized.c.push(serialized_caveat);
        }

        serialized
    }
}

impl TryFrom<V2JSerialization> for Macaroon {
    type Err = MacaroonError;
    fn try_from(ser: V2JSerialization) -> Result<Self, Self::Err> {
        if ser.i.is_some() && ser.i64.is_some() {
            return Err(MacaroonError::DeserializationError(String::from("Found i and i64 fields")));
        }
        if ser.l.is_some() && ser.l64.is_some() {
            return Err(MacaroonError::DeserializationError(String::from("Found l and l64 fields")));
        }
        if ser.s.is_some() && ser.s64.is_some() {
            return Err(MacaroonError::DeserializationError(String::from("Found s and s64 fields")));
        }

        let mut macaroon: Macaroon = Default::default();
        macaroon.identifier = match ser.i {
            Some(id) => id,
            None => {
                match ser.i64 {
                    Some(id) => String::from_utf8(id.from_base64()?)?,
                    None => {
                        return Err(MacaroonError::DeserializationError(String::from("No identifier \
                                                                                     found")))
                    }
                }
            }
        };

        macaroon.location = match ser.l {
            Some(loc) => Some(loc),
            None => {
                match ser.l64 {
                    Some(loc) => Some(String::from_utf8(loc.from_base64()?)?),
                    None => None,
                }
            }
        };

        macaroon.signature = match ser.s {
            Some(sig) => sig,
            None => {
                match ser.s64 {
                    Some(sig) => sig.from_base64()?,
                    None => {
                        return Err(MacaroonError::DeserializationError(String::from("No signature \
                                                                                     found")))
                    }
                }
            }
        };

        let mut caveat: Caveat = Default::default();
        for c in ser.c {
            caveat.id = match c.i {
                Some(id) => id,
                None => {
                    match c.i64 {
                        Some(id64) => String::from_utf8(id64.from_base64()?)?,
                        None => {
                            return Err(MacaroonError::DeserializationError(String::from("No caveat \
                                                                                         ID found")))
                        }
                    }
                }
            };
            caveat.location = match c.l {
                Some(loc) => Some(loc),
                None => {
                    match c.l64 {
                        Some(loc64) => Some(String::from_utf8(loc64.from_base64()?)?),
                        None => None,
                    }
                }
            };
            caveat.verifier_id = match c.v {
                Some(vid) => Some(vid),
                None => {
                    match c.v64 {
                        Some(vid64) => Some(vid64.from_base64()?),
                        None => None,
                    }
                }
            };
            macaroon.caveats.push(caveat);
            caveat = Default::default();
        }

        Ok(macaroon)
    }
}

pub fn serialize_v2j(macaroon: &Macaroon) -> Result<Vec<u8>, MacaroonError> {
    let serialized: String = serde_json::to_string(&V2JSerialization::from(macaroon))?;
    Ok(serialized.into_bytes())
}

pub fn deserialize_v2j(data: &Vec<u8>) -> Result<Macaroon, MacaroonError> {
    let v2j: V2JSerialization = serde_json::from_slice(data.as_slice())?;
    println!("{:?}", v2j);
    Macaroon::try_from(v2j)
}

#[cfg(test)]
mod tests {
    use super::super::super::macaroon::Macaroon;
    use super::super::Format;

    const SERIALIZED_V2J: &'static str = "{\"v\":2,\"l\":\"http://example.org/\",\"i\":\"keyid\",\
                                          \"c\":[{\"i\":\"account = 3735928559\"},{\"i\":\"user = \
                                          alice\"}],\"s64\":\
                                          \"S-lnzR6gxrJrr2pKlO6bBbFYhtoLqF6MQqk8jQ4SXvw\"}";
    const SIGNATURE_V2: [u8; 32] = [75, 233, 103, 205, 30, 160, 198, 178, 107, 175, 106, 74, 148,
                                    238, 155, 5, 177, 88, 134, 218, 11, 168, 94, 140, 66, 169, 60,
                                    141, 14, 18, 94, 252];

    #[test]
    fn test_deserialize_v2j() {
        let serialized_v2j: Vec<u8> = SERIALIZED_V2J.as_bytes().to_vec();
        let macaroon = super::deserialize_v2j(&serialized_v2j).unwrap();
        assert_eq!("http://example.org/", &macaroon.location.unwrap());
        assert_eq!("keyid", macaroon.identifier);
        assert_eq!(2, macaroon.caveats.len());
        assert_eq!("account = 3735928559", macaroon.caveats[0].id);
        assert_eq!(None, macaroon.caveats[0].verifier_id);
        assert_eq!(None, macaroon.caveats[0].location);
        assert_eq!("user = alice", macaroon.caveats[1].id);
        assert_eq!(None, macaroon.caveats[0].verifier_id);
        assert_eq!(None, macaroon.caveats[0].location);
        assert_eq!(SIGNATURE_V2.to_vec(), macaroon.signature);
    }

    #[test]
    fn test_serialize_deserialize_v2j() {
        let macaroon = Macaroon::create("http://example.org/", &SIGNATURE_V2, "keyid").unwrap();
        let serialized = macaroon.serialize(Format::V2J).unwrap();
        let other = Macaroon::deserialize(&serialized).unwrap();
        assert_eq!(macaroon, other);
    }
}