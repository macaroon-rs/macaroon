use serialize::base64::{STANDARD, ToBase64, FromBase64};
use std::str;
use super::super::caveat::CaveatBuilder;
use super::super::macaroon::Macaroon;
use super::super::error::MacaroonError;

// Version 1 fields
const LOCATION_V1: &'static str = "location";
const IDENTIFIER_V1: &'static str = "identifier";
const SIGNATURE_V1: &'static str = "signature";
const CID_V1: &'static str = "cid";
const VID_V1: &'static str = "vid";
const CL_V1: &'static str = "cl";

const HEADER_SIZE_V1: usize = 4;

fn serialize_as_packet<'r>(tag: &'r str, value: &'r [u8]) -> Vec<u8> {
    let mut packet: Vec<u8> = Vec::new();
    let size = HEADER_SIZE_V1 + 2 + tag.len() + value.len();
    packet.extend(packet_header(size));
    packet.extend_from_slice(tag.as_bytes());
    packet.extend_from_slice(" ".as_bytes());
    packet.extend_from_slice(value);
    packet.extend_from_slice("\n".as_bytes());

    packet
}

fn to_hex_char(value: u8) -> u8 {
    let hex = format!("{:1x}", value);
    hex.as_bytes()[0]
}

fn packet_header(size: usize) -> Vec<u8> {
    let mut header: Vec<u8> = Vec::new();
    header.push(to_hex_char(((size >> 12) & 15) as u8));
    header.push(to_hex_char(((size >> 8) & 15) as u8));
    header.push(to_hex_char(((size >> 4) & 15) as u8));
    header.push(to_hex_char((size & 15) as u8));

    header
}

pub fn serialize_v1(macaroon: &Macaroon) -> Result<Vec<u8>, MacaroonError> {
    let mut serialized: Vec<u8> = Vec::new();
    match macaroon.location {
        Some(ref location) => {
            serialized.extend(serialize_as_packet(LOCATION_V1, location.as_bytes()))
        }
        None => (),
    };
    serialized.extend(serialize_as_packet(IDENTIFIER_V1, macaroon.identifier.as_bytes()));
    for caveat in &macaroon.caveats {
        serialized.extend(serialize_as_packet(CID_V1, caveat.id.as_bytes()));
        match caveat.verifier_id {
            Some(ref verifier_id) => serialized.extend(serialize_as_packet(VID_V1, &verifier_id)),
            None => (),
        }
        match caveat.location {
            Some(ref location) => {
                serialized.extend(serialize_as_packet(CL_V1, location.as_bytes()))
            }
            None => (),
        }
    }
    serialized.extend(serialize_as_packet(SIGNATURE_V1, &macaroon.signature));
    Ok(serialized.to_base64(STANDARD).as_bytes().to_vec())
}

fn base64_decode(base64: &str) -> Result<Vec<u8>, MacaroonError> {
    Ok(base64.from_base64()?)
}

struct Packet {
    key: String,
    value: Vec<u8>,
}

fn deserialize_as_packets<'r>(data: &'r [u8],
                              mut packets: Vec<Packet>)
                              -> Result<Vec<Packet>, MacaroonError> {
    if data.len() == 0 {
        return Ok(packets);
    }
    let hex: &str = str::from_utf8(&data[..4])?;
    let size: usize = usize::from_str_radix(hex, 16)?;
    let packet_data = &data[4..size];
    let index = try!(get_split_index(packet_data));
    let (key_slice, value_slice) = packet_data.split_at(index);
    packets.push(Packet {
        key: String::from_utf8(key_slice.to_vec())?,
        value: value_slice[1..].to_vec(),
    });
    deserialize_as_packets(&data[size..], packets)
}

fn get_split_index(packet: &[u8]) -> Result<usize, MacaroonError> {
    match packet.iter().position(|&r| r == ' ' as u8) {
        Some(index) => Ok(index),
        None => return Err(MacaroonError::DeserializationError(String::from("Key/value error"))),
    }
}

pub fn deserialize_v1(base64: &Vec<u8>) -> Result<Macaroon, MacaroonError> {
    let data = try!(base64_decode(&String::from_utf8(base64.clone())?));
    let mut macaroon: Macaroon = Default::default();
    let mut builder: CaveatBuilder = CaveatBuilder::new();
    for packet in try!(deserialize_as_packets(data.as_slice(), Vec::new())) {
        match packet.key.as_str() {
            LOCATION_V1 => {
                macaroon.location = Some(String::from(String::from_utf8(packet.value)?.trim()))
            }
            IDENTIFIER_V1 => {
                macaroon.identifier = String::from(String::from_utf8(packet.value)?.trim())
            }
            SIGNATURE_V1 => {
                if builder.has_id() {
                    macaroon.caveats.push(builder.build()?);
                    builder = CaveatBuilder::new();
                }
                let mut signature: Vec<u8> = Vec::new();
                signature.extend_from_slice(&packet.value[..32]);
                macaroon.signature = signature;
            }
            CID_V1 => {
                if builder.has_id() {
                    macaroon.caveats.push(builder.build()?);
                    builder = CaveatBuilder::new();
                } else {
                    builder.add_id(String::from(String::from_utf8(packet.value)?.trim()));
                }
            }
            VID_V1 => builder.add_verifier_id(packet.value),
            CL_V1 => builder.add_location(String::from(String::from_utf8(packet.value)?.trim())),
            _ => return Err(MacaroonError::DeserializationError(String::from("Unknown key"))),
        };
    }
    Ok(macaroon)
}

#[cfg(test)]
mod tests {
    use super::super::super::macaroon::Macaroon;

    const SERIALIZED_V1: &'static str = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAyZnNpZ25hdHVyZSB83ueSURxbxvUoSFgF3-myTnheKOKpkwH51xHGCeOO9wo";
    const SERIALIZED_V1_WITH_CAVEAT: &'static str = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDJmc2lnbmF0dXJlIPVIB_bcbt-Ivw9zBrOCJWKjYlM9v3M5umF2XaS9JZ2HCg";
    const SIGNATURE_V1: [u8; 32] = [124, 222, 231, 146, 81, 28, 91, 198, 245, 40, 72, 88, 5, 223,
                                    233, 178, 78, 120, 94, 40, 226, 169, 147, 1, 249, 215, 17,
                                    198, 9, 227, 142, 247];
    const SIGNATURE_V1_WITH_CAVEAT: [u8; 32] = [245, 72, 7, 246, 220, 110, 223, 136, 191, 15, 115,
                                                6, 179, 130, 37, 98, 163, 98, 83, 61, 191, 115,
                                                57, 186, 97, 118, 93, 164, 189, 37, 157, 135];

    #[test]
    fn test_deserialize_v1() {
        let macaroon = super::deserialize_v1(&SERIALIZED_V1.as_bytes().to_vec()).unwrap();
        assert!(macaroon.location.is_some());
        assert_eq!("http://example.org/", &macaroon.location.unwrap());
        assert_eq!("keyid", &macaroon.identifier);
        assert_eq!(SIGNATURE_V1.to_vec(), macaroon.signature);
        let macaroon = super::deserialize_v1(&SERIALIZED_V1_WITH_CAVEAT.as_bytes().to_vec())
            .unwrap();
        assert!(macaroon.location.is_some());
        assert_eq!("http://example.org/", &macaroon.location.unwrap());
        assert_eq!("keyid", &macaroon.identifier);
        assert_eq!(1, macaroon.caveats.len());
        assert_eq!("account = 3735928559", macaroon.caveats[0].id);
        assert_eq!(None, macaroon.caveats[0].verifier_id);
        assert_eq!(None, macaroon.caveats[0].location);
        assert_eq!(SIGNATURE_V1_WITH_CAVEAT.to_vec(), macaroon.signature);
    }

    #[test]
    fn test_serialize_deserialize_v1() {
        let macaroon = Macaroon::create("http://example.org/", &SIGNATURE_V1, "keyid").unwrap();
        let serialized = macaroon.serialize(super::super::Format::V1).unwrap();
        let other = Macaroon::deserialize(&serialized).unwrap();
        assert_eq!(macaroon, other);
    }
}