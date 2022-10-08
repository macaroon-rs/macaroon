use std::{num, str, string};

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
