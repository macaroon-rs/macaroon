# macaroon Change Log

## Version 0.3.1 - UNRELEASED (macaroon)

Note: would increment to v0.4.0 if there are major changes.

## Version 0.3.0 - Oct 13, 2022 (macaroon)

This is a backwards-incompatible release with respect to serialized macaroon signatures, because the HMAC has changed. This version should have signatures interoperable with `libmacaroon-rs v0.1.x`, and with most popular Macaroon implementations in other languages.

- Revert HMAC back to SHA-256 (breaks signatures)
- Dependency updates
- Update Rust edition to 2021, and minimum required Rust version to v1.56
- Public API "flattened" (internal modules no longer exposed), and some internal cryptographic functions removed from API
- Fix several trivial panics deserializing tokens
- Flexible decoding of base64-encoded macaroons (either URL-safe base64 or "standard" base64)
- Refactor MacaroonError, MacaroonKey, and Macaroon::deserialize()

## Version 0.2.0 - Sep 24, 2021 (macaroon)

First release of [`macaroon`](https://crates.io/crates/macaroon) crate from the new [`macaroon-rs`](https://github.com/macaroon-rs) github organization.

Macaroon signatures created with this version are not compatible with prior releases, because of the HMAC change.

- Several refactors to code and API
- Dependencies updated
- Macaroon HMAC changed from SHA-256 to SHA-512-256

## Version 0.1.1 - Feb 22, 2017 (libmacaroon-rs)

- Coverage using [coveralls.io](https://coveralls.io/github/jacklund/libmacaroon-rs?branch=trunk)
- Expanded coverage of unit tests
- Bug fix for version 1 deserialization

## Version 0.1.0 - Feb 20, 2017 (libmacaroon-rs)

Initial commit. Functionality:

- Macaroons with first- and third-party caveats
- Serialization/Deserialization using [libmacaroons](https://github.com/rescrv/libmacaroons) version 1, 2, and 2J (JSON) formats
- Verification of first-party caveats using either exact string comparison or submitted verification function
- Verification of third-party caveats using discharge macaroons
