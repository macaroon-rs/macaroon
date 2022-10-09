use std::{num, str, string};

/// Represents all of the errors that can arise when creating, deserializing, or verifying macaroons.
///
/// `InitializationError` is only raised by the [`initialize`] function, when there is a problem
/// initializing the lower-level crypto library. `CryptoError` represents a runtime error when using
/// that library, or situations like zero-length ciphertext.
///
/// `IncompleteMacaroon` and `IncompleteCaveat` can occur when constructing or deserializing
/// [`Macaroon`] or [`Caveat`] structs, and expected fields are not present.
///
/// `DeserializationError` represents a broad category of issues when parsing a macaroon token in
/// any format.
///
/// `CaveatNotSatisfied`, `DischargeNotUsed`, and `InvalidSignature` are all errors that arise when
/// verifying a [`Macaroon`], and all represent a failure to authorize with the given key and set
/// of satisfiers.
#[derive(Debug)]
pub enum MacaroonError {
    InitializationError,
    CryptoError(&'static str),
    IncompleteMacaroon(&'static str),
    IncompleteCaveat(&'static str),
    DeserializationError(String),
    CaveatNotSatisfied(String),
    DischargeNotUsed,
    InvalidSignature,
}

impl From<serde_json::Error> for MacaroonError {
    fn from(error: serde_json::Error) -> MacaroonError {
        MacaroonError::DeserializationError(format!("{}", error))
    }
}

impl From<string::FromUtf8Error> for MacaroonError {
    fn from(error: string::FromUtf8Error) -> MacaroonError {
        MacaroonError::DeserializationError(format!("{}", error))
    }
}

impl From<base64::DecodeError> for MacaroonError {
    fn from(error: base64::DecodeError) -> MacaroonError {
        MacaroonError::DeserializationError(format!("{}", error))
    }
}

impl From<num::ParseIntError> for MacaroonError {
    fn from(error: num::ParseIntError) -> MacaroonError {
        MacaroonError::DeserializationError(format!("{}", error))
    }
}

impl From<str::Utf8Error> for MacaroonError {
    fn from(error: str::Utf8Error) -> MacaroonError {
        MacaroonError::DeserializationError(format!("{}", error))
    }
}

impl std::error::Error for MacaroonError {}

impl std::fmt::Display for MacaroonError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MacaroonError::InitializationError => write!(
                f,
                "Failed to initialize cryptographic library for this thread"
            ),
            MacaroonError::CryptoError(s) => write!(
                f,
                "Error performing lower-level cryptographic function: {}",
                s
            ),
            MacaroonError::IncompleteMacaroon(s) => {
                write!(f, "Macaroon was missing required field: {}", s)
            }
            MacaroonError::IncompleteCaveat(s) => {
                write!(f, "Caveat was missing required field: {}", s)
            }
            MacaroonError::DeserializationError(s) => {
                write!(f, "Failed to deserialize macaroon: {}", s)
            }
            MacaroonError::CaveatNotSatisfied(s) => write!(
                f,
                "Macaroon failed to verify because one or more caveats were not satisfied: {}",
                s
            ),
            MacaroonError::DischargeNotUsed => write!(
                f,
                "Macaroon failed to verify because one or more discharges were not used"
            ),
            MacaroonError::InvalidSignature => write!(
                f,
                "Macaroon failed to verify because signature did not match"
            ),
        }
    }
}
