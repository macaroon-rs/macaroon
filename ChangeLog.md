# libmacaroon-rs Change Log

## Version 0.1.1 - Feb 22, 2017

- Coverage using [coveralls.io](https://coveralls.io/github/jacklund/libmacaroon-rs?branch=master)
- Expanded coverage of unit tests
- Bug fix for version 1 deserialization

## Version 0.1.0 - Feb 20, 2017

Initial commit. Functionality:

- Macaroons with first- and third-party caveats
- Serialization/Deserialization using [libmacaroons](https://github.com/rescrv/libmacaroons) version 1, 2, and 2J (JSON) formats
- Verification of first-party caveats using either exact string comparison or submitted verification function
- Verification of third-party caveats using discharge macaroons