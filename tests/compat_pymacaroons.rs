use base64;
/// https://github.com/ecordell/pymacaroons/blob/master/tests/functional_tests/functional_tests.py
use macaroon::{Format, Macaroon, MacaroonError, MacaroonKey, NO_PAD_URL_SAFE_ENGINE};

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b).to_string())
        .collect::<Vec<String>>()
        .join("")
}

#[test]
fn test_basic_signature() {
    // note that this one test is the same as libmacaroons example, but that the other tests aren't
    let root_key = MacaroonKey::generate(b"this is our super secret key; only we should know it");
    let mac = Macaroon::create(
        Some("http://mybank/".into()),
        &root_key,
        "we used our secret key".into(),
    )
    .unwrap();
    assert_eq!(
        bytes_to_hex(mac.signature().as_ref()),
        "e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f"
    );
}

#[test]
fn test_first_party_caveat() {
    let root_key = MacaroonKey::generate(b"this is our super secret key; only we should know it");
    let mut mac = Macaroon::create(
        Some("http://mybank/".into()),
        &root_key,
        "we used our secret key".into(),
    )
    .unwrap();
    mac.add_first_party_caveat("test = caveat".into());
    assert_eq!(
        bytes_to_hex(mac.signature().as_ref()),
        "197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c23dbd67"
    );
}

#[test]
fn test_serializing() {
    let root_key = MacaroonKey::generate(b"this is our super secret key; only we should know it");
    let mut mac = Macaroon::create(
        Some("http://mybank/".into()),
        &root_key,
        "we used our secret key".into(),
    )
    .unwrap();
    mac.add_first_party_caveat("test = caveat".into());
    let b64_standard = "MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxNmNpZCB0ZXN0ID0gY2F2ZWF0CjAwMmZzaWduYXR1cmUgGXusegRK8zMyhluSZuJtSTvdZopmDkTYjOGpmMI9vWcK";
    let b64_url_safe =
        base64::encode_engine(base64::decode(b64_standard).unwrap(), &NO_PAD_URL_SAFE_ENGINE);
    assert_eq!(mac.serialize(Format::V1).unwrap(), b64_url_safe);

    let after_v1 = Macaroon::deserialize(mac.serialize(Format::V1).unwrap()).unwrap();
    let after_v2 = Macaroon::deserialize(mac.serialize(Format::V2).unwrap()).unwrap();
    let after_v2json = Macaroon::deserialize(mac.serialize(Format::V2JSON).unwrap()).unwrap();
    assert_eq!(mac, after_v1);
    assert_eq!(mac, after_v2);
    assert_eq!(mac, after_v2json);
}

#[test]
fn test_serializing_binary_id() {
    let root_key = MacaroonKey::generate(b"this is our super secret key; only we should know it");
    let identifier = base64::decode("AK2o+q0Aq9+bONkXw7ky7HAuhCLO9hhaMMc").unwrap();
    let mut mac = Macaroon::create(
        Some("http://mybank/".into()),
        &root_key,
        identifier.clone().into(),
    )
    .unwrap();
    mac.add_first_party_caveat("test = caveat".into());

    let after_v1 = Macaroon::deserialize(mac.serialize(Format::V1).unwrap()).unwrap();
    let after_v2 = Macaroon::deserialize(mac.serialize(Format::V2).unwrap()).unwrap();
    let after_v2json = Macaroon::deserialize(mac.serialize(Format::V2JSON).unwrap()).unwrap();
    assert_eq!(mac, after_v1);
    assert_eq!(mac, after_v2);
    assert_eq!(mac, after_v2json);
    println!(
        "v1:\t{:?}\nv2:\t{:?}\nmac:\t{:?}\nraw:\t{:?}",
        after_v1.identifier(),
        after_v2.identifier(),
        mac.identifier(),
        identifier
    );
    assert_eq!(mac.identifier(), identifier.clone().into());
    assert_eq!(after_v1.identifier(), identifier.clone().into());
    assert_eq!(after_v2.identifier(), identifier.clone().into());
    assert_eq!(after_v2json.identifier(), identifier.clone().into());
}

#[test]
fn test_deserializing_invalid() {
    assert!(matches!(
        Macaroon::deserialize("QA"),
        Err(MacaroonError::DeserializationError(_))
    ));
}

// test_serializing_strips_padding(: don't care about padding in output

#[test]
fn test_serializing_max_length_packet() {
    let root_key = MacaroonKey::generate(b"blah");
    let mut mac = Macaroon::create(Some("test".into()), &root_key, "secret".into()).unwrap();
    mac.add_first_party_caveat(vec![b'x'; 65526].into());
    assert!(mac.serialize(Format::V2).is_ok());
}

#[test]
fn test_serializing_too_long_packet() {
    let root_key = MacaroonKey::generate(b"blah");
    let mut mac = Macaroon::create(Some("test".into()), &root_key, "secret".into()).unwrap();
    mac.add_first_party_caveat(vec![b'x'; 65527].into());
    // TODO: implement a max size check
    //assert!(mac.serialize(Format::V2).is_err());
}

#[test]
fn test_deserializing() {
    // base
    let _mac = Macaroon::deserialize("MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxNmNpZCB0ZXN0ID0gY2F2ZWF0CjAwMmZzaWduYXR1cmUgGXusegRK8zMyhluSZuJtSTvdZopmDkTYjOGpmMI9vWcK").unwrap();

    // "binary" (byte array)
    let mac = Macaroon::deserialize(b"MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxNmNpZCB0ZXN0ID0gY2F2ZWF0CjAwMmZzaWduYXR1cmUgGXusegRK8zMyhluSZuJtSTvdZopmDkTYjOGpmMI9vWcK").unwrap();
    assert_eq!(
        bytes_to_hex(mac.signature().as_ref()),
        "197bac7a044af33332865b9266e26d493bdd668a660e44d88ce1a998c23dbd67"
    );

    // padding
    // this is apparently invalid?
    let mac = Macaroon::deserialize("MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxN2NpZCB0ZXN0ID0gYWNhdmVhdAowMDJmc2lnbmF0dXJlIJRJ_V3WNJQnqlVq5eez7spnltwU_AXs8NIRY739sHooCg==").unwrap();
    assert_eq!(
        bytes_to_hex(mac.signature().as_ref()),
        "9449fd5dd6349427aa556ae5e7b3eeca6796dc14fc05ecf0d21163bdfdb07a28"
    );
}

// test_serializing_json_v1: not implemented serialization

// test_deserializing_json_v2: not a valid signature length?

// there are some more complex examples, but most require resetting the libsodium nonce generation
// (to not be random), so can't reproduce
