use serde_json;
use serialize::base64::{STANDARD, ToBase64, FromBase64};
use std::convert::TryFrom;
use std::str;
use super::super::caveat::CaveatBuilder;
use super::super::macaroon::{Macaroon, MacaroonBuilder};
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

impl TryFrom<Macaroon> for V2JSerialization {
    type Err = MacaroonError;
    fn try_from(macaroon: Macaroon) -> Result<Self, Self::Err> {
        let mut serialized: V2JSerialization = V2JSerialization {
            v: 2,
            i: Some(macaroon.get_identifier().clone()),
            i64: None,
            l: macaroon.get_location().clone(),
            l64: None,
            c: Vec::new(),
            s: None,
            s64: Some(macaroon.get_signature().to_base64(STANDARD)),
        };
        for caveat in macaroon.get_caveats() {
            let serialized_caveat: CaveatV2J = CaveatV2J {
                i: Some(String::from(caveat.get_serialized_id()?)),
                i64: None,
                l: caveat.get_location().map(|s| String::from(s)),
                l64: None,
                v: caveat.get_verifier_id(),
                v64: None,
            };
            serialized.c.push(serialized_caveat);
        }

        Ok(serialized)
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

        let mut builder: MacaroonBuilder = MacaroonBuilder::new();
        builder.set_identifier(&match ser.i {
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
        });

        match ser.l {
            Some(loc) => builder.set_location(&loc),
            None => {
                match ser.l64 {
                    Some(loc) => builder.set_location(&String::from_utf8(loc.from_base64()?)?),
                    None => (),
                }
            }
        };

        builder.set_signature(&match ser.s {
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
        });

        let mut caveat_builder: CaveatBuilder = CaveatBuilder::new();
        for c in ser.c {
            caveat_builder.add_id(match c.i {
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
            });
            match c.l {
                Some(loc) => caveat_builder.add_location(loc),
                None => {
                    match c.l64 {
                        Some(loc64) => {
                            caveat_builder.add_location(String::from_utf8(loc64.from_base64()?)?)
                        }
                        None => (),
                    }
                }
            };
            match c.v {
                Some(vid) => caveat_builder.add_verifier_id(vid),
                None => {
                    match c.v64 {
                        Some(vid64) => caveat_builder.add_verifier_id(vid64.from_base64()?),
                        None => (),
                    }
                }
            };
            builder.add_caveat(caveat_builder.build()?);
            caveat_builder = CaveatBuilder::new();
        }

        Ok(builder.build()?)
    }
}

pub fn serialize_v2j(macaroon: &Macaroon) -> Result<Vec<u8>, MacaroonError> {
    let serialized: String = serde_json::to_string(&V2JSerialization::try_from(macaroon.clone())?)?;
    Ok(serialized.into_bytes())
}

pub fn deserialize_v2j(data: &Vec<u8>) -> Result<Macaroon, MacaroonError> {
    let v2j: V2JSerialization = serde_json::from_slice(data.as_slice())?;
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
        assert_eq!("http://example.org/", &macaroon.get_location().unwrap());
        assert_eq!("keyid", macaroon.get_identifier());
        assert_eq!(2, macaroon.get_caveats().len());
        assert_eq!("account = 3735928559",
                   macaroon.get_caveats()[0].get_predicate().unwrap());
        assert_eq!("user = alice",
                   macaroon.get_caveats()[1].get_predicate().unwrap());
        assert_eq!(SIGNATURE_V2.to_vec(), macaroon.get_signature());
    }

    #[test]
    fn test_serialize_deserialize_v2j() {
        let macaroon = Macaroon::create("http://example.org/", &SIGNATURE_V2, "keyid").unwrap();
        let serialized = macaroon.serialize(Format::V2J).unwrap();
        let other = Macaroon::deserialize(&serialized).unwrap();
        assert_eq!(macaroon, other);
    }
}