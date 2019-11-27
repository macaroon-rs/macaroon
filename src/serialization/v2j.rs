use serde_json;
use serde::{Serialize, Deserialize};
use std::str;
use caveat::{CaveatBuilder, CaveatType};
use Macaroon;
use error::MacaroonError;
use serialization::macaroon_builder::MacaroonBuilder;

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

impl V2JSerialization {

    fn from_macaroon(macaroon: Macaroon) -> Result<V2JSerialization, MacaroonError> {
        let mut serialized: V2JSerialization = V2JSerialization {
            v: 2,
            i: Some(macaroon.identifier().clone()),
            i64: None,
            l: macaroon.location().clone(),
            l64: None,
            c: Vec::new(),
            s: None,
            s64: Some(base64::encode_config(macaroon.signature(), base64::URL_SAFE)),
        };
        for caveat in macaroon.caveats() {
            match caveat.get_type() {
                CaveatType::FirstParty => {
                    let first_party = caveat.as_first_party().unwrap();
                    let serialized_caveat: CaveatV2J = CaveatV2J {
                        i: Some(first_party.predicate()),
                        i64: None,
                        l: None,
                        l64: None,
                        v: None,
                        v64: None,
                    };
                    serialized.c.push(serialized_caveat);
                }
                CaveatType::ThirdParty => {
                    let third_party = caveat.as_third_party().unwrap();
                    let serialized_caveat: CaveatV2J = CaveatV2J {
                        i: Some(third_party.id()),
                        i64: None,
                        l: Some(third_party.location()),
                        l64: None,
                        v: Some(third_party.verifier_id()),
                        v64: None,
                    };
                    serialized.c.push(serialized_caveat);
                }
            }
        }

        Ok(serialized)
    }
}

impl Macaroon {

    fn from_v2j(ser: V2JSerialization) -> Result<Macaroon, MacaroonError> {
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
                    Some(id) => String::from_utf8(base64::decode_config(&id, base64::URL_SAFE)?)?,
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
                if let Some(loc) = ser.l64 {
                    builder.set_location(&String::from_utf8(base64::decode_config(&loc, base64::URL_SAFE)?)?)
                }
            }
        };

        builder.set_signature(&match ser.s {
            Some(sig) => sig,
            None => {
                match ser.s64 {
                    Some(sig) => base64::decode_config(&sig, base64::URL_SAFE)?,
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
                        Some(id64) => String::from_utf8(base64::decode_config(&id64, base64::URL_SAFE)?)?,
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
                    if let Some(loc64) = c.l64 {
                        caveat_builder.add_location(String::from_utf8(base64::decode_config(&loc64, base64::URL_SAFE)?)?)
                    }
                }
            };
            match c.v {
                Some(vid) => caveat_builder.add_verifier_id(vid),
                None => {
                    if let Some(vid64) = c.v64 {
                        caveat_builder.add_verifier_id(base64::decode_config(&vid64, base64::URL_SAFE)?)
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
    let serialized: String = serde_json::to_string(&V2JSerialization::from_macaroon(macaroon.clone())?)?;
    Ok(serialized.into_bytes())
}

pub fn deserialize_v2j(data: &[u8]) -> Result<Macaroon, MacaroonError> {
    let v2j: V2JSerialization = serde_json::from_slice(data)?;
    Macaroon::from_v2j(v2j)
}

#[cfg(test)]
mod tests {
    use Macaroon;
    use super::super::Format;

    const SERIALIZED_V2J: &str = "{\"v\":2,\"l\":\"http://example.org/\",\"i\":\"keyid\",\
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
        assert_eq!("http://example.org/", &macaroon.location().unwrap());
        assert_eq!("keyid", macaroon.identifier());
        assert_eq!(2, macaroon.caveats().len());
        assert_eq!("account = 3735928559",
                   macaroon.caveats()[0].as_first_party().unwrap().predicate());
        assert_eq!("user = alice",
                   macaroon.caveats()[1].as_first_party().unwrap().predicate());
        assert_eq!(SIGNATURE_V2.to_vec(), macaroon.signature());
    }

    #[test]
    fn test_serialize_deserialize_v2j() {
        let mut macaroon = Macaroon::create("http://example.org/", &SIGNATURE_V2, "keyid").unwrap();
        macaroon.add_first_party_caveat("user = alice");
        macaroon.add_third_party_caveat("https://auth.mybank.com/", b"my key", "keyid");
        let serialized = macaroon.serialize(Format::V2J).unwrap();
        let other = Macaroon::deserialize(&serialized).unwrap();
        assert_eq!(macaroon, other);
    }
}
