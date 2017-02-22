# libmacaroon-rs

Rust implementation of [macaroons](https://research.google.com/pubs/pub41892.html).

[![Build Status](https://travis-ci.org/jacklund/libmacaroon-rs.svg?branch=master)](https://travis-ci.org/jacklund/libmacaroon-rs)
[![crates.io](https://img.shields.io/crates/v/macaroon.svg)](https://crates.io/crates/macaroon)
[![Coverage Status](https://coveralls.io/repos/github/jacklund/libmacaroon-rs/badge.svg?branch=master)](https://coveralls.io/github/jacklund/libmacaroon-rs?branch=master)

- [Documentation](https://docs.rs/macaroon)
- [Entry at `crates.io`](https://crates.io/crates/macaroon)

This started as a project to learn Rust, and sort of mophed into a fully-functional Macaroon implementation.

## What are Macaroons?

Macaroons are bearer tokens (similar to cookies) which encode within them criteria within which the
authorization is allowed to take place (referred to as "caveats"). For instance, authorization could
be restricted to a particular user, account, time of day, really anything. These criteria can be either
evaluated locally (a "first-party caveat"), or using special macaroons ("discharge macaroons") generated
by a third party (a "third-party caveat").

A first-party caveat consists simply of a predicate which, when evaluated as true, authorizes the caveat.
The predicate is a string which is either evaluated using strict string comparison (`satisfy_exact`),
or interpreted using a provided function (`satisfy_general`).

A third-party caveat consists of a location string, an identifier, and a specially-generated signing key
to authenticate the generated discharge macaroons. The key and identifier is passed to the third-party
who generates the discharge macaroons. The receiver then binds each discharge macaroon to the original
macaroon.

During verification of a third-party caveat, a discharge macaroon is found from those received whose identifier
matches that of the caveat. The binding signature is verified, and the discharge macaroon's caveats are verified
using the same process as the original macaroon.

The macaroon is considered authorized only if all its caveats are authorized by the above process.

## Functionality Implemented

- Creating macaroons, and adding first- and third-party caveats
- Serialization - versions 1, 2 & 2J are supported
- Validation (mostly for validating deserialized macaroons)
- Creation of discharge macaroons
- Verification of both first- and third-party caveats (the latter using discharge macaroons)

## Requirements

For now, you need to use the nightly build of Rust, because of `serde_derive`'s dependence on
`#[proc_macro_derive]`, which is experimental (but should be merged into stable soon).

To use the nightly compiler:

```bash
$ rustup default nightly
```

## Usage
In your `Cargo.toml`:
```
[dependencies]
macaroon = 0.1.0
```

### Examples
```rust
extern crate macaroon;

use macaroon::{Macaroon, Verifier};

// Initialize to make crypto primitives thread-safe
macaroon::initialize().unwrap(); // Force panic if initialization fails

// Create our macaroon
let mut macaroon = match Macaroon::create("location", b"key", "id") {
    Ok(macaroon) => macaroon,
    Err(error) => panic!("Error creating macaroon: {:?}", error),
};

// Add our first-party caveat. We say that only someone with account 12345678
// is authorized to access whatever the macaroon is protecting
// Note that we can add however many of these we want, with different predicates
macaroon.add_first_party_caveat("account = 12345678");

// Now we verify the macaroon
// First we create the verifier
let mut verifier = Verifier::new();

// We assert that the account number is "12345678"
verifier.satisfy_exact("account = 12345678");

// Now we verify the macaroon. It should return `Ok(true)` if the user is authorized
match macaroon.verify(b"key", &mut verifier) {
    Ok(true) => println!("Macaroon verified!"),
    Ok(false) => println!("Macaroon verification failed"),
    Err(error) => println!("Error validating macaroon: {:?}", error),
}

// Now, let's add a third-party caveat, which just says that we need our third party
// to authorize this for us as well.
macaroon.add_third_party_caveat("https://auth.mybank", b"different key", "caveat id");

// When we're ready to verify a third-party caveat, we use the location
// (in this case, "https://auth.mybank") to retrieve the discharge macaroons we use to verify.
// These would be created by the third party like so:
let mut discharge = match Macaroon::create("http://auth.mybank/",
                                           b"different key",
                                           "caveat id") {
    Ok(discharge) => discharge,
    Err(error) => panic!("Error creating discharge macaroon: {:?}", error),
};
// And this is the criterion the third party requires for authorization
discharge.add_first_party_caveat("account = 12345678");

// Once we receive the discharge macaroon, we bind it to the original macaroon
macaroon.bind(&mut discharge);

// Then we can verify using the same verifier (which will verify both the existing
// first-party caveat and the third party one)
verifier.add_discharge_macaroons(&vec![discharge]);
match macaroon.verify(b"key", &mut verifier) {
    Ok(true) => println!("Macaroon verified!"),
    Ok(false) => println!("Macaroon verification failed"),
    Err(error) => println!("Error validating macaroon: {:?}", error),
}
```