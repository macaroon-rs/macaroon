use serialize::base64::{STANDARD, ToBase64, FromBase64};
use std::str;
use caveat::{CaveatBuilder, CaveatType};
use Macaroon;
use error::MacaroonError;
use serialization::macaroon_builder::MacaroonBuilder;

// Version 1 fields
const LOCATION: &'static str = "location";
const IDENTIFIER: &'static str = "identifier";
const SIGNATURE: &'static str = "signature";
const CID: &'static str = "cid";
const VID: &'static str = "vid";
const CL: &'static str = "cl";

const HEADER_SIZE: usize = 4;

fn serialize_as_packet<'r>(tag: &'r str, value: &'r [u8]) -> Vec<u8> {
    let mut packet: Vec<u8> = Vec::new();
    let size = HEADER_SIZE + 2 + tag.len() + value.len();
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
    match macaroon.location() {
        Some(ref location) => {
            serialized.extend(serialize_as_packet(LOCATION, location.as_bytes()))
        }
        None => (),
    };
    serialized.extend(serialize_as_packet(IDENTIFIER, macaroon.identifier().as_bytes()));
    for caveat in macaroon.caveats() {
        match caveat.get_type() {
            CaveatType::FirstParty => {
                let first_party = caveat.as_first_party().unwrap();
                serialized.extend(serialize_as_packet(CID, first_party.predicate().as_bytes()));
            }
            CaveatType::ThirdParty => {
                let third_party = caveat.as_third_party().unwrap();
                serialized.extend(serialize_as_packet(CID, third_party.id().as_bytes()));
                serialized.extend(serialize_as_packet(VID, third_party.verifier_id().as_slice()));
                serialized.extend(serialize_as_packet(CL, third_party.location().as_bytes()))
            }
        }
    }
    serialized.extend(serialize_as_packet(SIGNATURE, macaroon.signature()));
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
    let index = try!(split_index(packet_data));
    let (key_slice, value_slice) = packet_data.split_at(index);
    packets.push(Packet {
        key: String::from_utf8(key_slice.to_vec())?,
        // skip beginning space and terminating \n
        value: value_slice[1..value_slice.len()-1].to_vec(),
    });
    deserialize_as_packets(&data[size..], packets)
}

fn split_index(packet: &[u8]) -> Result<usize, MacaroonError> {
    match packet.iter().position(|&r| r == ' ' as u8) {
        Some(index) => Ok(index),
        None => return Err(MacaroonError::DeserializationError(String::from("Key/value error"))),
    }
}

pub fn deserialize_v1(base64: &Vec<u8>) -> Result<Macaroon, MacaroonError> {
    let data = try!(base64_decode(&String::from_utf8(base64.clone())?));
    let mut builder: MacaroonBuilder = MacaroonBuilder::new();
    let mut caveat_builder: CaveatBuilder = CaveatBuilder::new();
    for packet in try!(deserialize_as_packets(data.as_slice(), Vec::new())) {
        match packet.key.as_str() {
            LOCATION => {
                builder.set_location(&String::from_utf8(packet.value)?);
            }
            IDENTIFIER => {
                builder.set_identifier(&String::from_utf8(packet.value)?);
            }
            SIGNATURE => {
                if caveat_builder.has_id() {
                    builder.add_caveat(caveat_builder.build()?);
                    caveat_builder = CaveatBuilder::new();
                }
                if packet.value.len() != 32 {
                    error!("deserialize_v1: Deserialization error - signature length is {}",
                           packet.value.len());
                    return Err(MacaroonError::DeserializationError(String::from("Illegal signature \
                                                                                 length in \
                                                                                 packet")));
                }
                builder.set_signature(&packet.value);
            }
            CID => {
                if caveat_builder.has_id() {
                    builder.add_caveat(caveat_builder.build()?);
                    caveat_builder = CaveatBuilder::new();
                    caveat_builder.add_id(String::from(String::from_utf8(packet.value)?));
                } else {
                    caveat_builder.add_id(String::from(String::from_utf8(packet.value)?));
                }
            }
            VID => {
                caveat_builder.add_verifier_id(packet.value);
            }
            CL => {
                caveat_builder.add_location(String::from(String::from_utf8(packet.value)?))
            }
            _ => return Err(MacaroonError::DeserializationError(String::from("Unknown key"))),
        };
    }
    Ok(builder.build()?)
}

#[cfg(test)]
mod tests {
    use Macaroon;

    #[test]
    fn test_deserialize_v1() {
        let mut serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAyZnNpZ25hdHVyZSB83ueSURxbxvUoSFgF3-myTnheKOKpkwH51xHGCeOO9wo";
        let mut signature: [u8; 32] = [124, 222, 231, 146, 81, 28, 91, 198, 245, 40, 72, 88, 5,
                                       223, 233, 178, 78, 120, 94, 40, 226, 169, 147, 1, 249, 215,
                                       17, 198, 9, 227, 142, 247];
        let macaroon = super::deserialize_v1(&serialized.as_bytes().to_vec()).unwrap();
        assert!(macaroon.location().is_some());
        assert_eq!("http://example.org/", &macaroon.location().unwrap());
        assert_eq!("keyid", macaroon.identifier());
        assert_eq!(signature.to_vec(), macaroon.signature());
        serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDJmc2lnbmF0dXJlIPVIB_bcbt-Ivw9zBrOCJWKjYlM9v3M5umF2XaS9JZ2HCg";
        signature = [245, 72, 7, 246, 220, 110, 223, 136, 191, 15, 115, 6, 179, 130, 37, 98, 163,
                     98, 83, 61, 191, 115, 57, 186, 97, 118, 93, 164, 189, 37, 157, 135];
        let macaroon = super::deserialize_v1(&serialized.as_bytes().to_vec()).unwrap();
        assert!(macaroon.location().is_some());
        assert_eq!("http://example.org/", &macaroon.location().unwrap());
        assert_eq!("keyid", macaroon.identifier());
        assert_eq!(1, macaroon.caveats().len());
        assert_eq!("account = 3735928559",
                   macaroon.caveats()[0].as_first_party().unwrap().predicate());
        assert_eq!(signature.to_vec(), macaroon.signature());
    }

    #[test]
    fn test_deserialize_v1_two_caveats() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDE1Y2lkIHVzZXIgPSBhbGljZQowMDJmc2lnbmF0dXJlIEvpZ80eoMaya69qSpTumwWxWIbaC6hejEKpPI0OEl78Cg";
        let signature = [75, 233, 103, 205, 30, 160, 198, 178, 107, 175, 106, 74, 148, 238, 155,
                         5, 177, 88, 134, 218, 11, 168, 94, 140, 66, 169, 60, 141, 14, 18, 94, 252];
        let macaroon = super::deserialize_v1(&serialized.as_bytes().to_vec()).unwrap();
        assert!(macaroon.location().is_some());
        assert_eq!("http://example.org/", &macaroon.location().unwrap());
        assert_eq!("keyid", macaroon.identifier());
        assert_eq!(signature.to_vec(), macaroon.signature());
        assert_eq!(2, macaroon.caveats().len());
        assert_eq!("account = 3735928559",
                   macaroon.caveats()[0].as_first_party().unwrap().predicate());
        assert_eq!("user = alice",
                   macaroon.caveats()[1].as_first_party().unwrap().predicate());
    }

    #[test]
    fn test_serialize_deserialize_v1() {
        let mut macaroon: Macaroon = Macaroon::create("http://example.org/", b"my key", "keyid")
            .unwrap();
        macaroon.add_first_party_caveat("account = 3735928559");
        macaroon.add_first_party_caveat("user = alice");
        macaroon.add_third_party_caveat("https://auth.mybank.com", b"caveat key", "caveat");
        let serialized = macaroon.serialize(super::super::Format::V1).unwrap();
        let deserialized = Macaroon::deserialize(&serialized).unwrap();
        assert_eq!(macaroon, deserialized);
    }
}