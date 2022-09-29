# macaroon Change Log

## UNRELEASED

- Dependency updates

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
