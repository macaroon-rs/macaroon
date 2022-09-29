use crate::caveat::{Caveat, CaveatBuilder};
use crate::error::MacaroonError;
use crate::serialization::macaroon_builder::MacaroonBuilder;
use crate::{ByteString, Macaroon, Result};
use std::str;

// Version 1 fields
const LOCATION: &str = "location";
const IDENTIFIER: &str = "identifier";
const SIGNATURE: &str = "signature";
const CID: &str = "cid";
const VID: &str = "vid";
const CL: &str = "cl";

const HEADER_SIZE: usize = 4;

fn serialize_as_packet<'r>(tag: &'r str, value: &'r [u8]) -> Vec<u8> {
    let mut packet: Vec<u8> = Vec::new();
    let size = HEADER_SIZE + 2 + tag.len() + value.len();
    packet.extend(packet_header(size));
    packet.extend_from_slice(tag.as_bytes());
    packet.extend_from_slice(b" ");
    packet.extend_from_slice(value);
    packet.extend_from_slice(b"\n");

    packet
}

fn to_hex_char(value: u8) -> u8 {
    let hex = format!("{:1x}", value);
    hex.as_bytes()[0]
}

fn packet_header(size: usize) -> Vec<u8> {
    vec![
        to_hex_char(((size >> 12) & 15) as u8),
        to_hex_char(((size >> 8) & 15) as u8),
        to_hex_char(((size >> 4) & 15) as u8),
        to_hex_char((size & 15) as u8),
    ]
}

pub fn serialize(macaroon: &Macaroon) -> Result<Vec<u8>> {
    let mut serialized: Vec<u8> = Vec::new();
    if let Some(ref location) = macaroon.location() {
        serialized.extend(serialize_as_packet(LOCATION, location.as_bytes()));
    };
    serialized.extend(serialize_as_packet(IDENTIFIER, &macaroon.identifier().0));
    for c in macaroon.caveats() {
        match c {
            Caveat::FirstParty(fp) => {
                serialized.extend(serialize_as_packet(CID, &fp.predicate().0));
            }
            Caveat::ThirdParty(tp) => {
                serialized.extend(serialize_as_packet(CID, &tp.id().0));
                serialized.extend(serialize_as_packet(VID, &tp.verifier_id().0));
                serialized.extend(serialize_as_packet(CL, tp.location().as_bytes()))
            }
        }
    }
    serialized.extend(serialize_as_packet(SIGNATURE, &macaroon.signature()));
    Ok(base64::encode_config(&serialized, base64::URL_SAFE)
        .as_bytes()
        .to_vec())
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    Ok(base64::decode_config(s, base64::URL_SAFE)?)
}

struct Packet {
    key: String,
    value: Vec<u8>,
}

fn deserialize_as_packets(data: &[u8], mut packets: Vec<Packet>) -> Result<Vec<Packet>> {
    if data.is_empty() {
        return Ok(packets);
    }
    let hex: &str = str::from_utf8(&data[..4])?;
    let size: usize = usize::from_str_radix(hex, 16)?;
    let packet_data = &data[4..size];
    let index = split_index(packet_data)?;
    let (key_slice, value_slice) = packet_data.split_at(index);
    packets.push(Packet {
        key: String::from_utf8(key_slice.to_vec())?,
        // skip beginning space and terminating \n
        value: value_slice[1..value_slice.len() - 1].to_vec(),
    });
    deserialize_as_packets(&data[size..], packets)
}

fn split_index(packet: &[u8]) -> Result<usize> {
    match packet.iter().position(|&r| r == b' ') {
        Some(index) => Ok(index),
        None => Err(MacaroonError::DeserializationError(String::from(
            "Key/value error",
        ))),
    }
}

pub fn deserialize(base64: &[u8]) -> Result<Macaroon> {
    let data = base64_decode(&String::from_utf8(base64.to_vec())?)?;
    let mut builder: MacaroonBuilder = MacaroonBuilder::new();
    let mut caveat_builder: CaveatBuilder = CaveatBuilder::new();
    for packet in deserialize_as_packets(data.as_slice(), Vec::new())? {
        match packet.key.as_str() {
            LOCATION => {
                builder.set_location(&String::from_utf8(packet.value)?);
            }
            IDENTIFIER => {
                builder.set_identifier(ByteString(packet.value));
            }
            SIGNATURE => {
                if caveat_builder.has_id() {
                    builder.add_caveat(caveat_builder.build()?);
                    caveat_builder = CaveatBuilder::new();
                }
                if packet.value.len() != 32 {
                    error!(
                        "deserialize_v1: Deserialization error - signature length is {}",
                        packet.value.len()
                    );
                    return Err(MacaroonError::DeserializationError(String::from(
                        "Illegal signature \
                         length in \
                         packet",
                    )));
                }
                builder.set_signature(&packet.value);
            }
            CID => {
                if caveat_builder.has_id() {
                    builder.add_caveat(caveat_builder.build()?);
                    caveat_builder = CaveatBuilder::new();
                    caveat_builder.add_id(ByteString(packet.value));
                } else {
                    caveat_builder.add_id(ByteString(packet.value));
                }
            }
            VID => {
                caveat_builder.add_verifier_id(ByteString(packet.value));
            }
            CL => caveat_builder.add_location(String::from_utf8(packet.value)?),
            _ => {
                return Err(MacaroonError::DeserializationError(String::from(
                    "Unknown key",
                )))
            }
        };
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use crate::{ByteString, Caveat, Macaroon, MacaroonKey};

    #[test]
    fn test_deserialize() {
        let mut serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAyZnNpZ25hdHVyZSB83ueSURxbxvUoSFgF3-myTnheKOKpkwH51xHGCeOO9wo";
        let mut signature: MacaroonKey = [
            124, 222, 231, 146, 81, 28, 91, 198, 245, 40, 72, 88, 5, 223, 233, 178, 78, 120, 94,
            40, 226, 169, 147, 1, 249, 215, 17, 198, 9, 227, 142, 247,
        ]
        .into();
        let macaroon = super::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        assert!(macaroon.location().is_some());
        assert_eq!("http://example.org/", &macaroon.location().unwrap());
        assert_eq!(ByteString::from("keyid"), macaroon.identifier());
        assert_eq!(signature, macaroon.signature());
        serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDJmc2lnbmF0dXJlIPVIB_bcbt-Ivw9zBrOCJWKjYlM9v3M5umF2XaS9JZ2HCg";
        signature = [
            245, 72, 7, 246, 220, 110, 223, 136, 191, 15, 115, 6, 179, 130, 37, 98, 163, 98, 83,
            61, 191, 115, 57, 186, 97, 118, 93, 164, 189, 37, 157, 135,
        ]
        .into();
        let macaroon = super::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        assert!(macaroon.location().is_some());
        assert_eq!("http://example.org/", &macaroon.location().unwrap());
        assert_eq!(ByteString::from("keyid"), macaroon.identifier());
        assert_eq!(1, macaroon.caveats().len());
        let predicate = match &macaroon.caveats()[0] {
            Caveat::FirstParty(fp) => fp.predicate(),
            _ => ByteString::default(),
        };
        assert_eq!(ByteString::from("account = 3735928559"), predicate);
        assert_eq!(signature, macaroon.signature());
    }

    #[test]
    fn test_deserialize_two_caveats() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDE1Y2lkIHVzZXIgPSBhbGljZQowMDJmc2lnbmF0dXJlIEvpZ80eoMaya69qSpTumwWxWIbaC6hejEKpPI0OEl78Cg";
        let signature: MacaroonKey = [
            75, 233, 103, 205, 30, 160, 198, 178, 107, 175, 106, 74, 148, 238, 155, 5, 177, 88,
            134, 218, 11, 168, 94, 140, 66, 169, 60, 141, 14, 18, 94, 252,
        ]
        .into();
        let macaroon = super::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        assert!(macaroon.location().is_some());
        assert_eq!("http://example.org/", &macaroon.location().unwrap());
        assert_eq!(ByteString::from("keyid"), macaroon.identifier());
        assert_eq!(signature, macaroon.signature());
        assert_eq!(2, macaroon.caveats().len());
        let predicate = match &macaroon.caveats()[0] {
            Caveat::FirstParty(fp) => fp.predicate(),
            _ => ByteString::default(),
        };
        assert_eq!(ByteString::from("account = 3735928559"), predicate);
        let predicate = match &macaroon.caveats()[1] {
            Caveat::FirstParty(fp) => fp.predicate(),
            _ => ByteString::default(),
        };
        assert_eq!(ByteString::from("user = alice"), predicate);
    }

    #[test]
    fn test_serialize_deserialize() {
        let mut macaroon: Macaroon = Macaroon::create(
            Some("http://example.org/".into()),
            &"my key".into(),
            "keyid".into(),
        )
        .unwrap();
        macaroon.add_first_party_caveat("account = 3735928559".into());
        macaroon.add_first_party_caveat("user = alice".into());
        macaroon.add_third_party_caveat(
            "https://auth.mybank.com",
            &"caveat key".into(),
            "caveat".into(),
        );
        let serialized = macaroon.serialize(super::super::Format::V1).unwrap();
        let deserialized = Macaroon::deserialize(&serialized).unwrap();
        assert_eq!(macaroon, deserialized);
    }
}
