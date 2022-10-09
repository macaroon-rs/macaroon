use std::{num, str, string};

/// Represents all of the errors that can arise when creating, deserializing, or verifying macaroons.
#[derive(Debug)]
pub enum MacaroonError {
    /// Only raised by the [`initialize()`](crate::initialize) function, when there is a problem
    /// initializing the lower-level crypto library
    InitializationError,

    /// Represents a runtime error in the lower-level cryptographic library, or situations like
    /// zero-length ciphertext.
    CryptoError(&'static str),

    /// Can occur when constructing or deserializing a [`Macaroon`](crate::Macaroon) and expected fields are not present.
    IncompleteMacaroon(&'static str),

    /// Can occur when constructing or deserializing [`Caveat`](crate::Caveat) and expected fields are not present.
    IncompleteCaveat(&'static str),

    /// Represents a broad category of issues when parsing a macaroon token in any format.
    DeserializationError(String),

    /// Arises when verifying a [`Macaroon`](crate::Macaroon), when it has any caveat not
    /// satisfied by any "exact" or "general" satisfiers configured on the
    /// [`Verifier`](crate::Verifier). Indicates a failure to authenticate the macaroon.
    CaveatNotSatisfied(String),

    /// Arises when verifying a [`Macaroon`](crate::Macaroon), with a set of discharges configured
    /// on the verifier, and one or more are not used during the verification process. Indicates a
    /// failure to authenticate the macaroon.
    DischargeNotUsed,

    /// Arises when verifying a [`Macaroon`](crate::Macaroon), and the signature does not match
    /// what is expected. Indicates a failure to authenticate the macaroon.
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
