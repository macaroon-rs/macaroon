// Examples from libmacaroons reference implementation README:
// https://github.com/rescrv/libmacaroons

use base64;
use macaroon::{ByteString, Caveat, Format, Macaroon, MacaroonKey, NO_PAD_URL_SAFE_ENGINE, Verifier};

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b).to_string())
        .collect::<Vec<String>>()
        .join("")
}

#[test]
fn creating_macaroons() {
    let root_key = MacaroonKey::generate(b"this is our super secret key; only we should know it");
    let mac = Macaroon::create(
        Some("http://mybank/".into()),
        &root_key,
        "we used our secret key".into(),
    )
    .unwrap();

    assert_eq!(mac.identifier(), "we used our secret key".into());
    assert_eq!(mac.location(), Some("http://mybank/".into()));

    assert_eq!(
        bytes_to_hex(mac.signature().as_ref()),
        "e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f"
    );

    let b64_standard = "MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAyZnNpZ25hdHVyZSDj2eApCFJsTAA5rhURQRXZf91ovyujebNCqvD2F9BVLwo";
    let b64_url_safe =
        base64::encode_engine(base64::decode(b64_standard).unwrap(), &NO_PAD_URL_SAFE_ENGINE);
    assert_eq!(mac.serialize(Format::V1).unwrap(), b64_url_safe);
}

#[test]
fn adding_caveats() {
    let root_key = MacaroonKey::generate(b"this is our super secret key; only we should know it");
    let mut mac = Macaroon::create(
        Some("http://mybank".into()),
        &root_key,
        "we used our secret key".into(),
    )
    .unwrap();
    mac.add_first_party_caveat("account = 3735928559".into());
    assert_eq!(
        bytes_to_hex(mac.signature().as_ref()),
        "1efe4763f290dbce0c1d08477367e11f4eee456a64933cf662d79772dbb82128"
    );

    mac.add_first_party_caveat("time < 2020-01-01T00:00".into());
    assert_eq!(
        bytes_to_hex(mac.signature().as_ref()),
        "b5f06c8c8ef92f6c82c6ff282cd1f8bd1849301d09a2db634ba182536a611c49"
    );

    mac.add_first_party_caveat("email = alice@example.org".into());
    assert_eq!(
        bytes_to_hex(mac.signature().as_ref()),
        "ddf553e46083e55b8d71ab822be3d8fcf21d6bf19c40d617bb9fb438934474b6"
    );

    // serialize and deserialize using V1
    let mac2 = Macaroon::deserialize(&mac.serialize(Format::V1).unwrap()).unwrap();
    assert_eq!(
        bytes_to_hex(mac2.signature().as_ref()),
        "ddf553e46083e55b8d71ab822be3d8fcf21d6bf19c40d617bb9fb438934474b6"
    );
}

// this doesn't actually implement datetime checking, because we don't have 'chrono' or similar
// pulled in. Instead, just doing string/byte comparison, which should just about work for these
// test cases.
fn check_time(caveat: &ByteString) -> bool {
    let caveat: &[u8] = caveat.as_ref();
    if !caveat.starts_with(b"time < ") {
        return false;
    }
    // around time the doc was written, between 2014 and 2020
    let now = b"2018-01-01T00:00";
    if caveat.len() != now.len() + 7 {
        return false;
    }
    let when = &caveat[7..];
    String::from_utf8_lossy(now) < String::from_utf8_lossy(when)
}

#[test]
fn test_check_time() {
    assert_eq!(check_time(&"time < 2020-01-01T00:00".into()), true);
    assert_eq!(check_time(&"time < 2014-01-01T00:00".into()), false);
    assert_eq!(check_time(&"account = 3735928559".into()), false);
}

#[test]
fn verifying_macaroons() {
    let key = MacaroonKey::generate(b"this is our super secret key; only we should know it");
    let mut mac = Macaroon::create(
        Some("http://mybank/".into()),
        &key,
        "we used our secret key".into(),
    )
    .unwrap();
    mac.add_first_party_caveat("account = 3735928559".into());
    mac.add_first_party_caveat("time < 2020-01-01T00:00".into());
    mac.add_first_party_caveat("email = alice@example.org".into());

    let mut ver = Verifier::default();
    assert!(ver.verify(&mac, &key, Default::default()).is_err());
    ver.satisfy_exact("account = 3735928559".into());
    ver.satisfy_exact("email = alice@example.org".into());
    ver.satisfy_exact("IP = 127.0.0.1".into());
    ver.satisfy_exact("browser = Chrome".into());
    ver.satisfy_exact("action = deposit".into());
    ver.satisfy_general(check_time);

    assert!(ver.verify(&mac, &key, Default::default()).is_ok());

    // additional caveat which we are prepared for
    let mut mac_action = mac.clone();
    mac_action.add_first_party_caveat("action = deposit".into());
    assert!(ver.verify(&mac_action, &key, Default::default()).is_ok());

    // additional caveat which we are not prepared for
    let mut mac_os = mac.clone();
    mac_os.add_first_party_caveat("OS = Windows XP".into());
    assert!(ver.verify(&mac_os, &key, Default::default()).is_err());

    // wrong secret key used in verification
    let wrong_key = MacaroonKey::generate(b"this is not the secret we were looking for");
    assert!(ver.verify(&mac, &wrong_key, Default::default()).is_err());

    // "Incompetent hackers trying to change the signature"
    let b64_standard = "MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDIwY2lkIHRpbWUgPCAyMDIwLTAxLTAxVDAwOjAwCjAwMjJjaWQgZW1haWwgPSBhbGljZUBleGFtcGxlLm9yZwowMDJmc2lnbmF0dXJlID8f19FL+bkC9p/aoMmIecC7GxdOcLVyUnrv6lJMM7NSCg==";
    let bad_mac = Macaroon::deserialize(b64_standard).unwrap();
    assert_eq!(mac.location(), bad_mac.location());
    assert_eq!(mac.identifier(), bad_mac.identifier());
    assert_eq!(mac.caveats(), bad_mac.caveats());
    assert_ne!(mac.signature(), bad_mac.signature());
    assert!(ver.verify(&bad_mac, &key, Default::default()).is_err());
}

#[test]
fn third_party_macaroons() {
    let key = MacaroonKey::generate(
        b"this is a different super-secret key; never use the same secret twice",
    );
    let mut mac = Macaroon::create(
        Some("http://mybank/".into()),
        &key,
        "we used our other secret key".into(),
    )
    .unwrap();
    mac.add_first_party_caveat("account = 3735928559".into());
    assert_eq!(
        bytes_to_hex(mac.signature().as_ref()),
        "1434e674ad84fdfdc9bc1aa00785325c8b6d57341fc7ce200ba4680c80786dda"
    );

    let caveat_key = MacaroonKey::generate(b"4; guaranteed random by a fair toss of the dice");
    mac.add_third_party_caveat(
        "http://auth.mybank/".into(),
        &caveat_key,
        "this was how we remind auth of key/pred".into(),
    );
    // In the example, libsodium none generation is overriden, so the verifier_id is always the
    // same:
    // "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA027FAuBYhtHwJ58FX6UlVNFtFsGxQHS7uD_w_dedwv4Jjw7UorCREw5rXbRqIKhr"
    // We don't do that here, so can't actually verify that the signatures match perfectly.
    match &mac.third_party_caveats()[0] {
        Caveat::FirstParty(_) => assert!(false),
        Caveat::ThirdParty(tp) => {
            assert_eq!(tp.location(), "http://auth.mybank/");
            assert_eq!(tp.id(), "this was how we remind auth of key/pred".into());
            /*
            assert_eq!(tp.verifier_id(),
                base64::decode_config("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA027FAuBYhtHwJ58FX6UlVNFtFsGxQHS7uD_w_dedwv4Jjw7UorCREw5rXbRqIKhr", base64::URL_SAFE).unwrap().into(),
            );
            */
        }
    };
    /*
    assert_eq!(
        bytes_to_hex(mac.signature().as_ref()),
        "d27db2fd1f22760e4c3dae8137e2d8fc1df6c0741c18aed4b97256bf78d1f55c"
    );
    */

    let mut discharge_mac = Macaroon::create(
        Some("http://auth.mybank/".into()),
        &caveat_key,
        "this was how we remind auth of key/pred".into(),
    )
    .unwrap();
    discharge_mac.add_first_party_caveat("time < 2020-01-01T00:00".into());
    assert_eq!(
        bytes_to_hex(discharge_mac.signature().as_ref()),
        "2ed1049876e9d5840950274b579b0770317df54d338d9d3039c7c67d0d91d63c"
    );

    let mut bound_mac = discharge_mac.clone();
    mac.bind(&mut bound_mac);
    /*
    assert_eq!(
        bytes_to_hex(discharge_mac.signature().as_ref()),
        "d115ef1c133b1126978d5ab27f69d99ba9d0468cd6c1b7e47b8c1c59019cb019"
    );
    */

    let mut ver = Verifier::default();
    ver.satisfy_exact("account = 3735928559".into());
    ver.satisfy_exact("time < 2020-01-01T00:00".into());
    assert!(ver.verify(&mac, &key, vec![discharge_mac]).is_err());
    assert!(ver.verify(&mac, &key, vec![bound_mac]).is_ok());
}
