use serialize::base64::{STANDARD, ToBase64, FromBase64};
use std::error::Error;
use std::str;
use super::macaroon::{Caveat, Macaroon};
use super::error::MacaroonError;

// Version 1 fields
const LOCATION_V1: &'static str = "location";
const IDENTIFIER_V1: &'static str = "identifier";
const SIGNATURE_V1: &'static str = "signature";
const CID_V1: &'static str = "cid";
const VID_V1: &'static str = "vid";
const CL_V1: &'static str = "cl";

const HEADER_SIZE_V1: usize = 4;

// Version 2 fields
const EOS_V2: u8 = 0;
const LOCATION_V2: u8 = 1;
const IDENTIFIER_V2: u8 = 2;
const VID_V2: u8 = 4;
const SIGNATURE_V2: u8 = 6;

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

const VARINT_PACK_SIZE: usize = 128;

fn varint_size(size: usize) -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut my_size: usize = size;
    while my_size >= VARINT_PACK_SIZE {
        buffer.push(((my_size & (VARINT_PACK_SIZE - 1)) | VARINT_PACK_SIZE) as u8);
        my_size >>= 7;
    }

    buffer
}

fn serialize_field_v2(tag: u8, value: &Vec<u8>, buffer: &mut Vec<u8>) {
    buffer.push(tag);
    buffer.extend(varint_size(value.len()));
    buffer.extend(value);
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
            Some(ref verifier_id) => {
                serialized.extend(serialize_as_packet(VID_V1, verifier_id.as_bytes()))
            }
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

pub fn serialize_v2(macaroon: &Macaroon) -> Result<Vec<u8>, MacaroonError> {
    let mut buffer: Vec<u8> = Vec::new();
    buffer.push(2); // version
    match macaroon.location {
        Some(ref location) => {
            serialize_field_v2(LOCATION_V2, &location.as_bytes().to_vec(), &mut buffer)
        }
        None => (),
    };
    serialize_field_v2(IDENTIFIER_V2,
                       &macaroon.identifier.as_bytes().to_vec(),
                       &mut buffer);
    buffer.push(EOS_V2);
    for caveat in &macaroon.caveats {
        match caveat.location {
            Some(ref location) => {
                serialize_field_v2(LOCATION_V2, &location.as_bytes().to_vec(), &mut buffer)
            }
            None => (),
        }
        serialize_field_v2(IDENTIFIER_V2, &caveat.id.as_bytes().to_vec(), &mut buffer);
        match caveat.verifier_id {
            Some(ref id) => serialize_field_v2(VID_V2, &id.as_bytes().to_vec(), &mut buffer),
            None => (),
        }
        buffer.push(EOS_V2);
    }
    buffer.push(EOS_V2);
    serialize_field_v2(SIGNATURE_V2, &macaroon.signature, &mut buffer);
    Ok(buffer)
}

#[allow(unused_variables)]
pub fn serialize_v2j(macaroon: &Macaroon) -> Result<Vec<u8>, MacaroonError> {
    unimplemented!()
}

macro_rules! try_utf8 {
    ($x: expr) => (
        {
            match String::from_utf8($x) {
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
        key: try_utf8!(key_slice.to_vec()),
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
    let data = try!(base64_decode(&try_utf8!(base64.clone())));
    let mut macaroon: Macaroon = Default::default();
    let mut caveat: Caveat = Default::default();
    for packet in try!(deserialize_as_packets(data.as_slice(), Vec::new())) {
        match packet.key.as_str() {
            LOCATION_V1 => macaroon.location = Some(String::from(try_utf8!(packet.value).trim())),
            IDENTIFIER_V1 => macaroon.identifier = String::from(try_utf8!(packet.value).trim()),
            SIGNATURE_V1 => {
                if !caveat.id.is_empty() {
                    macaroon.caveats.push(caveat);
                    caveat = Default::default();
                }
                let mut signature: Vec<u8> = Vec::new();
                signature.extend_from_slice(&packet.value[..32]);
                macaroon.signature = signature;
            }
            CID_V1 => {
                if caveat.id.is_empty() {
                    caveat.id = String::from(try_utf8!(packet.value).trim());
                } else {
                    macaroon.caveats.push(caveat);
                    caveat = Default::default();
                }
            }
            VID_V1 => caveat.verifier_id = Some(String::from(try_utf8!(packet.value).trim())),
            CL_V1 => caveat.location = Some(String::from(try_utf8!(packet.value).trim())),
            _ => return Err(MacaroonError::DeserializationError(String::from("Unknown key"))),
        };
    }
    Ok(macaroon)
}

struct V2Deserializer<'r> {
    data: &'r [u8],
    index: usize,
}

impl<'r> V2Deserializer<'r> {
    pub fn new(data: &Vec<u8>) -> V2Deserializer {
        V2Deserializer {
            data: data,
            index: 0,
        }
    }

    fn get_byte(&mut self) -> Result<u8, MacaroonError> {
        if self.index > self.data.len() - 1 {
            return Err(MacaroonError::DeserializationError(String::from("Buffer overrun")));
        }
        let byte = self.data[self.index];
        self.index += 1;
        Ok(byte)
    }

    pub fn get_tag(&mut self) -> Result<u8, MacaroonError> {
        self.get_byte()
    }

    pub fn get_eos(&mut self) -> Result<u8, MacaroonError> {
        let eos = try!(self.get_byte());
        match eos {
            EOS_V2 => Ok(eos),
            _ => Err(MacaroonError::DeserializationError(String::from("Expected EOS"))),
        }
    }

    pub fn get_field(&mut self) -> Result<Vec<u8>, MacaroonError> {
        let size: usize = try!(self.get_field_size());
        if size + self.index > self.data.len() {
            return Err(MacaroonError::DeserializationError(String::from("Unexpected end of \
                                                                         field")));
        }

        let field: Vec<u8> = self.data[self.index..self.index + size].to_vec();
        self.index += size;
        Ok(field)
    }

    fn get_field_size(&mut self) -> Result<usize, MacaroonError> {
        let mut size: usize = 0;
        let mut shift: usize = 0;
        let mut byte: u8;
        while shift <= 63 {
            byte = try!(self.get_byte());
            if byte & 128 != 0 {
                size |= ((byte & 127) << shift) as usize;
            } else {
                size |= (byte << shift) as usize;
                return Ok(size);
            }
            shift += 7;
        }
        Err(MacaroonError::DeserializationError(String::from("Error in field size")))
    }
}

#[allow(unused_variables)]
pub fn deserialize_v2(data: &Vec<u8>) -> Result<Macaroon, MacaroonError> {
    let mut macaroon: Macaroon = Default::default();
    let mut deserializer: V2Deserializer = V2Deserializer::new(data);
    if try!(deserializer.get_byte()) != 2 {
        return Err(MacaroonError::DeserializationError(String::from("Wrong version number")));
    }
    let mut tag: u8 = try!(deserializer.get_tag());
    match tag {
        LOCATION_V2 => macaroon.location = Some(try_utf8!(try!(deserializer.get_field()))),
        IDENTIFIER_V2 => macaroon.identifier = try_utf8!(try!(deserializer.get_field())),
        _ => return Err(MacaroonError::DeserializationError(String::from("Identifier not found"))),
    }
    if macaroon.location.is_some() {
        tag = try!(deserializer.get_tag());
        match tag {
            IDENTIFIER_V2 => macaroon.identifier = try_utf8!(try!(deserializer.get_field())),
            _ => {
                return Err(MacaroonError::DeserializationError(String::from("Identifier not \
                                                                             found")))
            }
        }
    }
    try!(deserializer.get_eos());
    tag = try!(deserializer.get_tag());
    while tag != EOS_V2 {
        let mut caveat: Caveat = Default::default();
        match tag {
            LOCATION_V2 => {
                let field: Vec<u8> = try!(deserializer.get_field());
                caveat.location = Some(try_utf8!(field));
            }
            IDENTIFIER_V2 => caveat.id = try_utf8!(try!(deserializer.get_field())),
            _ => {
                return Err(MacaroonError::DeserializationError(String::from("Caveat identifier \
                                                                             not found")))
            }
        }
        if caveat.location.is_some() {
            tag = try!(deserializer.get_tag());
            match tag {
                IDENTIFIER_V2 => {
                    let field: Vec<u8> = try!(deserializer.get_field());
                    caveat.id = try_utf8!(field);
                }
                _ => {
                    return Err(MacaroonError::DeserializationError(String::from("Caveat identifier \
                                                                                 not found")))
                }
            }
        }
        tag = try!(deserializer.get_tag());
        match tag {
            VID_V2 => {
                let field: Vec<u8> = try!(deserializer.get_field());
                caveat.verifier_id = Some(try_utf8!(field));
                macaroon.caveats.push(caveat);
                try!(deserializer.get_eos());
                tag = try!(deserializer.get_tag());
            }
            EOS_V2 => {
                macaroon.caveats.push(caveat);
                tag = try!(deserializer.get_tag());
            }
            _ => {
                return Err(MacaroonError::DeserializationError(String::from("Unexpected caveat \
                                                                             tag found")))
            }
        }
    }
    tag = try!(deserializer.get_tag());
    if tag == SIGNATURE_V2 {
        macaroon.signature = try!(deserializer.get_field());
    } else {
        return Err(MacaroonError::DeserializationError(String::from("Unexpected tag found")));
    }
    Ok(macaroon)
}

#[allow(unused_variables)]
pub fn deserialize_v2j(data: &Vec<u8>) -> Result<Macaroon, MacaroonError> {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use serialize::base64::FromBase64;
    use super::super::macaroon::{Format, Macaroon};

    const SERIALIZED_V1: &'static str = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAyZnNpZ25hdHVyZSB83ueSURxbxvUoSFgF3-myTnheKOKpkwH51xHGCeOO9wo";
    const SERIALIZED_V1_WITH_CAVEAT: &'static str = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDJmc2lnbmF0dXJlIPVIB_bcbt-Ivw9zBrOCJWKjYlM9v3M5umF2XaS9JZ2HCg";
    const SERIALIZED_V2: &'static str = "AgETaHR0cDovL2V4YW1wbGUub3JnLwIFa2V5aWQAAhRhY2NvdW50ID0gMzczNTkyODU1OQACDHVzZXIgPSBhbGljZQAABiBL6WfNHqDGsmuvakqU7psFsViG2guoXoxCqTyNDhJe_A==";
    const SIGNATURE_V1: [u8; 32] = [124, 222, 231, 146, 81, 28, 91, 198, 245, 40, 72, 88, 5, 223,
                                    233, 178, 78, 120, 94, 40, 226, 169, 147, 1, 249, 215, 17,
                                    198, 9, 227, 142, 247];
    const SIGNATURE_V1_WITH_CAVEAT: [u8; 32] = [245, 72, 7, 246, 220, 110, 223, 136, 191, 15, 115,
                                                6, 179, 130, 37, 98, 163, 98, 83, 61, 191, 115,
                                                57, 186, 97, 118, 93, 164, 189, 37, 157, 135];
    const SIGNATURE_V2: [u8; 32] = [75, 233, 103, 205, 30, 160, 198, 178, 107, 175, 106, 74, 148,
                                    238, 155, 5, 177, 88, 134, 218, 11, 168, 94, 140, 66, 169, 60,
                                    141, 14, 18, 94, 252];

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
        let macaroon = Macaroon::create("http://example.org/", SIGNATURE_V1, "keyid").unwrap();
        let serialized = macaroon.serialize(Format::V1).unwrap();
        let other = Macaroon::deserialize(&serialized).unwrap();
        assert_eq!(macaroon, other);
    }

    #[test]
    fn test_deserialize_v2() {
        let serialized_v2: Vec<u8> = SERIALIZED_V2.from_base64().unwrap();
        let macaroon = super::deserialize_v2(&serialized_v2).unwrap();
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
}