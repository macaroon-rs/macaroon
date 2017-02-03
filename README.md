# libmacaroon-rs

Rust implementation of [macaroons](https://research.google.com/pubs/pub41892.html).

Macaroons are basically cookies which allow you to specify authorization and delegation criteria in a secure manner.

## Functionality Implemented So Far

- Macaroons and their caveats
- Serialization - versions 1, 2 & 2J are supported
- First-party caveats
- Validation (mostly for validating deserialized macaroons)

## To Do

- Verification
- Third-party caveats