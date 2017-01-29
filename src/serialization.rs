use serialize::base64::{STANDARD, ToBase64, FromBase64};
use std::error::Error;
use std::str;
use super::macaroon::Macaroon;
use super::error::MacaroonError;

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

#[allow(unused_variables)]
pub fn serialize_v1(macaroon: &Macaroon) -> Result<String, MacaroonError> {
    let mut serialized: Vec<u8> = Vec::new();
    serialized.extend(serialize_as_packet(LOCATION, macaroon.location.as_bytes()));
    serialized.extend(serialize_as_packet(IDENTIFIER, macaroon.identifier.as_bytes()));
    for caveat in &macaroon.caveats {
        serialized.extend(serialize_as_packet(CID, caveat.id.as_bytes()));
        if caveat.verifier_id.is_some() {
            serialized.extend(serialize_as_packet(VID, caveat.verifier_id.unwrap().as_bytes()));
        }
        if caveat.location.is_some() {
            serialized.extend(serialize_as_packet(CL, caveat.location.unwrap().as_bytes()));
        }
    }
    serialized.extend(serialize_as_packet(SIGNATURE, &macaroon.signature));
    Ok(serialized.to_base64(STANDARD))
}

#[allow(unused_variables)]
pub fn serialize_v2(macaroon: &Macaroon) -> Result<String, MacaroonError> {
    Ok("".to_string())
}

#[allow(unused_variables)]
pub fn serialize_v2j(macaroon: &Macaroon) -> Result<String, MacaroonError> {
    Ok("".to_string())
}

macro_rules! try_utf8 {
    ($x: expr) => (
        {
            let mut vector: Vec<u8> = Vec::new();
            vector.extend_from_slice($x);
            match String::from_utf8(vector) {
                Ok(value) => value,
                Err(error) => return Err(MacaroonError::DeserializationError(String::from(error.description()))),
            }
        }
    )
}

fn base64_decode(base64: &str) -> Result<Vec<u8>, MacaroonError> {
    match base64.from_base64() {
        Ok(value) => Ok(value),
        Err(error) => Err(MacaroonError::DeserializationError(String::from(error.description()))),
    }
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
    let size: usize = match str::from_utf8(&data[..4]) {
        Ok(hex) => {
            match usize::from_str_radix(hex, 16) {
                Ok(value) => value,
                Err(error) => return Err(MacaroonError::DeserializationError(String::from(error.description()))),
            }
        }
        Err(error) => {
            return Err(MacaroonError::DeserializationError(String::from(error.description())))
        }
    };
    let packet_data = &data[4..size];
    let index = try!(get_split_index(packet_data));
    let (key_slice, value_slice) = packet_data.split_at(index);
    packets.push(Packet {
        key: try_utf8!(key_slice),
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

pub fn deserialize_v1(base64: &str) -> Result<Macaroon, MacaroonError> {
    let data = try!(base64_decode(base64));
    println!("{:?}", data);
    let mut macaroon: Macaroon = Default::default();
    for packet in try!(deserialize_as_packets(data.as_slice(), Vec::new())) {
        match packet.key.as_str() {
            LOCATION => macaroon.location = String::from(try_utf8!(&packet.value).trim()),
            IDENTIFIER => macaroon.identifier = String::from(try_utf8!(&packet.value).trim()),
            SIGNATURE => {
                let mut signature: Vec<u8> = Vec::new();
                signature.extend_from_slice(&packet.value[..32]);
                macaroon.signature = signature;
            }
            _ => return Err(MacaroonError::DeserializationError(String::from("Unknown key"))),
        };
    }
    Ok(macaroon)
}

#[allow(unused_variables)]
pub fn deserialize_v2(data: &str) -> Result<Macaroon, MacaroonError> {
    unimplemented!()
}

#[allow(unused_variables)]
pub fn deserialize_v2j(data: &str) -> Result<Macaroon, MacaroonError> {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use serialize::base64::FromBase64;
    use super::super::macaroon::{Format, Macaroon};

    const SERIALIZED_V1: &'static str = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAyZnNpZ25hdHVyZSB83ueSURxbxvUoSFgF3-myTnheKOKpkwH51xHGCeOO9wo";
    const SIGNATURE: [u8; 32] = [124, 222, 231, 146, 81, 28, 91, 198, 245, 40, 72, 88, 5, 223,
                                 233, 178, 78, 120, 94, 40, 226, 169, 147, 1, 249, 215, 17, 198,
                                 9, 227, 142, 247];

    #[test]
    fn test_deserialize_v1() {
        let macaroon = super::deserialize_v1(&SERIALIZED_V1).unwrap();
        assert_eq!("http://example.org/", &macaroon.location);
        assert_eq!("keyid", &macaroon.identifier);
        assert_eq!(SIGNATURE.to_vec(), macaroon.signature);
    }

    #[test]
    fn test_serialize_deserialize_v1() {
        let macaroon = Macaroon::create("http://example.org/", SIGNATURE, "keyid").unwrap();
        let serialized = macaroon.serialize(Format::V1).unwrap();
        println!("{:?}", serialized);
        let other = Macaroon::deserialize(&serialized).unwrap();
        assert_eq!(macaroon, other);
    }
}