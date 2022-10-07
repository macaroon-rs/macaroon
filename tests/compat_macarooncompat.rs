/// Conversion of compatability tests from the 'macarooncompat' project:
/// https://github.com/go-macaroon/macarooncompat/blob/master/compat_test.go
use macaroon::{Macaroon, MacaroonKey};

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b).to_string())
        .collect::<Vec<String>>()
        .join("")
}

#[test]
fn libmacaroons_no_caveat() {
    // about: "no caveats, from libmacaroons example"
    // NOTE: compared to libmacaroons, there is a missing trailing slash on the 'location'
    let root_key = MacaroonKey::generate(b"this is our super secret key; only we should know it");
    let mac = Macaroon::create(
        Some("http://mybank".into()),
        &root_key,
        "we used our secret key".into(),
    )
    .unwrap();
    // expectSignature: "e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f"
    assert_eq!(
        bytes_to_hex(mac.signature().as_ref()),
        "e3d9e02908526c4c0039ae15114115d97fdd68bf2ba379b342aaf0f617d0552f"
    );
}

#[test]
fn libmacaroons_one_caveat() {
    // about: "one caveat, from libmacaroons example"
    let root_key = MacaroonKey::generate(b"this is our super secret key; only we should know it");
    let mut mac = Macaroon::create(
        Some("http://mybank".into()),
        &root_key,
        "we used our secret key".into(),
    )
    .unwrap();
    mac.add_first_party_caveat("account = 3735928559".into());
    // expectSignature: "1efe4763f290dbce0c1d08477367e11f4eee456a64933cf662d79772dbb82128"
    assert_eq!(
        bytes_to_hex(mac.signature().as_ref()),
        "1efe4763f290dbce0c1d08477367e11f4eee456a64933cf662d79772dbb82128"
    );
}

#[test]
fn libmacaroons_two_caveats() {
    // about: "two caveats, from libmacaroons example",
    let root_key = MacaroonKey::generate(b"this is our super secret key; only we should know it");
    let mut mac = Macaroon::create(
        Some("http://mybank".into()),
        &root_key,
        "we used our secret key".into(),
    )
    .unwrap();
    mac.add_first_party_caveat("account = 3735928559".into());
    mac.add_first_party_caveat("time < 2015-01-01T00:00".into());
    // expectSignature: "696665d0229f9f801b588bb3f68bbdb806b26d1fbcd40ca22d9017bce4a075f1"
    assert_eq!(
        bytes_to_hex(mac.signature().as_ref()),
        "696665d0229f9f801b588bb3f68bbdb806b26d1fbcd40ca22d9017bce4a075f1"
    );
}

#[test]
fn libmacaroons_three_caveats() {
    // about: "three caveats, from libmacaroons example",
    let root_key = MacaroonKey::generate(b"this is our super secret key; only we should know it");
    let mut mac = Macaroon::create(
        Some("http://mybank".into()),
        &root_key,
        "we used our secret key".into(),
    )
    .unwrap();
    mac.add_first_party_caveat("account = 3735928559".into());
    mac.add_first_party_caveat("time < 2015-01-01T00:00".into());
    mac.add_first_party_caveat("email = alice@example.org".into());
    // expectSignature: "882e6d59496ed5245edb7ab5b8839ecd63e5d504e54839804f164070d8eed952"
    assert_eq!(
        bytes_to_hex(mac.signature().as_ref()),
        "882e6d59496ed5245edb7ab5b8839ecd63e5d504e54839804f164070d8eed952"
    );
}

#[test]
fn libmacaroons_one_caveat_second() {
    // about: "one caveat, from second libmacaroons example",
    let root_key = MacaroonKey::generate(
        b"this is a different super-secret key; never use the same secret twice",
    );
    let mut mac = Macaroon::create(
        Some("http://mybank".into()),
        &root_key,
        "we used our other secret key".into(),
    )
    .unwrap();
    mac.add_first_party_caveat("account = 3735928559".into());
    assert_eq!(
        bytes_to_hex(mac.signature().as_ref()),
        "1434e674ad84fdfdc9bc1aa00785325c8b6d57341fc7ce200ba4680c80786dda"
    );
}

// TODO: more macarooncompat coverage
