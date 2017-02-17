use caveat::{CaveatBuilder, CaveatType};
use Macaroon;
use error::MacaroonError;
use serialization::macaroon_builder::MacaroonBuilder;

// Version 2 fields
const EOS_V2: u8 = 0;
const LOCATION_V2: u8 = 1;
const IDENTIFIER_V2: u8 = 2;
const VID_V2: u8 = 4;
const SIGNATURE_V2: u8 = 6;

const VARINT_PACK_SIZE: usize = 128;

fn varint_size(size: usize) -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut my_size: usize = size;
    while my_size >= VARINT_PACK_SIZE {
        buffer.push(((my_size & (VARINT_PACK_SIZE - 1)) | VARINT_PACK_SIZE) as u8);
        my_size >>= 7;
    }
    buffer.push(my_size as u8);

    buffer
}

fn serialize_field_v2(tag: u8, value: &[u8], buffer: &mut Vec<u8>) {
    buffer.push(tag);
    buffer.extend(varint_size(value.len()));
    buffer.extend(value);
}

pub fn serialize_v2(macaroon: &Macaroon) -> Result<Vec<u8>, MacaroonError> {
    let mut buffer: Vec<u8> = Vec::new();
    buffer.push(2); // version
    match macaroon.get_location() {
        Some(ref location) => {
            serialize_field_v2(LOCATION_V2, &location.as_bytes().to_vec(), &mut buffer)
        }
        None => (),
    };
    serialize_field_v2(IDENTIFIER_V2,
                       &macaroon.get_identifier().as_bytes().to_vec(),
                       &mut buffer);
    buffer.push(EOS_V2);
    for caveat in macaroon.get_caveats() {
        match caveat.get_type() {
            CaveatType::FirstParty => {
                let first_party = caveat.as_first_party().unwrap();
                serialize_field_v2(IDENTIFIER_V2,
                                   &first_party.get_predicate().as_bytes().to_vec(),
                                   &mut buffer);
                buffer.push(EOS_V2);
            }
            CaveatType::ThirdParty => {
                let third_party = caveat.as_third_party().unwrap();
                serialize_field_v2(LOCATION_V2,
                                   third_party.get_location().as_bytes(),
                                   &mut buffer);
                serialize_field_v2(IDENTIFIER_V2, third_party.get_id().as_bytes(), &mut buffer);
                serialize_field_v2(VID_V2,
                                   third_party.get_verifier_id().as_slice(),
                                   &mut buffer);
                buffer.push(EOS_V2);
            }
        }
    }
    buffer.push(EOS_V2);
    serialize_field_v2(SIGNATURE_V2, macaroon.get_signature(), &mut buffer);
    Ok(buffer)
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

pub fn deserialize_v2(data: &Vec<u8>) -> Result<Macaroon, MacaroonError> {
    let mut builder: MacaroonBuilder = MacaroonBuilder::new();
    let mut deserializer: V2Deserializer = V2Deserializer::new(data);
    if try!(deserializer.get_byte()) != 2 {
        return Err(MacaroonError::DeserializationError(String::from("Wrong version number")));
    }
    let mut tag: u8 = try!(deserializer.get_tag());
    match tag {
        LOCATION_V2 => builder.set_location(&String::from_utf8(try!(deserializer.get_field()))?),
        IDENTIFIER_V2 => {
            builder.set_identifier(&String::from_utf8(try!(deserializer.get_field()))?)
        }
        _ => return Err(MacaroonError::DeserializationError(String::from("Identifier not found"))),
    }
    if builder.has_location() {
        tag = try!(deserializer.get_tag());
        match tag {
            IDENTIFIER_V2 => {
                builder.set_identifier(&String::from_utf8(try!(deserializer.get_field()))?);
            }
            _ => {
                return Err(MacaroonError::DeserializationError(String::from("Identifier not \
                                                                             found")))
            }
        }
    }
    try!(deserializer.get_eos());
    tag = try!(deserializer.get_tag());
    while tag != EOS_V2 {
        let mut caveat_builder: CaveatBuilder = CaveatBuilder::new();
        match tag {
            LOCATION_V2 => {
                let field: Vec<u8> = try!(deserializer.get_field());
                caveat_builder.add_location(String::from_utf8(field)?);
            }
            IDENTIFIER_V2 => {
                caveat_builder.add_id(String::from_utf8(try!(deserializer.get_field()))?)
            }
            _ => {
                return Err(MacaroonError::DeserializationError(String::from("Caveat identifier \
                                                                             not found")))
            }
        }
        if caveat_builder.has_location() {
            tag = try!(deserializer.get_tag());
            match tag {
                IDENTIFIER_V2 => {
                    let field: Vec<u8> = try!(deserializer.get_field());
                    caveat_builder.add_id(String::from_utf8(field)?);
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
                caveat_builder.add_verifier_id(field);
                builder.add_caveat(caveat_builder.build()?);
                try!(deserializer.get_eos());
                tag = try!(deserializer.get_tag());
            }
            EOS_V2 => {
                builder.add_caveat(caveat_builder.build()?);
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
        let sig: Vec<u8> = try!(deserializer.get_field());
        if sig.len() != 32 {
            return Err(MacaroonError::DeserializationError(String::from("Bad signature length")));
        }
        builder.set_signature(&sig);
    } else {
        return Err(MacaroonError::DeserializationError(String::from("Unexpected tag found")));
    }
    Ok(builder.build()?)
}

#[cfg(test)]
mod tests {
    use serialize::base64::FromBase64;
    use caveat;
    use serialization::macaroon_builder::MacaroonBuilder;

    const SERIALIZED_V2: &'static str = "AgETaHR0cDovL2V4YW1wbGUub3JnLwIFa2V5aWQAAhRhY2NvdW50ID0gMzczNTkyODU1OQACDHVzZXIgPSBhbGljZQAABiBL6WfNHqDGsmuvakqU7psFsViG2guoXoxCqTyNDhJe_A==";
    const SIGNATURE_V2: [u8; 32] = [75, 233, 103, 205, 30, 160, 198, 178, 107, 175, 106, 74, 148,
                                    238, 155, 5, 177, 88, 134, 218, 11, 168, 94, 140, 66, 169, 60,
                                    141, 14, 18, 94, 252];

    #[test]
    fn test_deserialize_v2() {
        let serialized_v2: Vec<u8> = SERIALIZED_V2.from_base64().unwrap();
        let macaroon = super::deserialize_v2(&serialized_v2).unwrap();
        assert_eq!("http://example.org/", &macaroon.get_location().unwrap());
        assert_eq!("keyid", macaroon.get_identifier());
        assert_eq!(2, macaroon.get_caveats().len());
        assert_eq!("account = 3735928559",
                   macaroon.get_caveats()[0].as_first_party().unwrap().get_predicate());
        assert_eq!("user = alice",
                   macaroon.get_caveats()[1].as_first_party().unwrap().get_predicate());
        assert_eq!(SIGNATURE_V2.to_vec(), macaroon.get_signature());
    }

    #[test]
    fn test_serialize_v2() {
        let mut builder = MacaroonBuilder::new();
        builder.add_caveat(box caveat::new_first_party("account = 3735928559"));
        builder.add_caveat(box caveat::new_first_party("user = alice"));
        builder.set_location("http://example.org/");
        builder.set_identifier("keyid");
        builder.set_signature(&SIGNATURE_V2);
        let serialized = super::serialize_v2(&builder.build().unwrap()).unwrap();
        assert_eq!(SERIALIZED_V2.from_base64().unwrap(), serialized);
    }
}