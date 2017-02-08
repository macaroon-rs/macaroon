use serde_json;
use serialize::base64;
use std::{num, str, string};

#[derive(Debug)]
pub enum MacaroonError {
    InitializationError,
    HashFailed,
    NotUTF8(str::Utf8Error),
    UnknownSerialization,
    DeserializationError(String),
    BadMacaroon(&'static str),
    KeyError(&'static str),
    DecryptionError(&'static str),
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

impl From<base64::FromBase64Error> for MacaroonError {
    fn from(error: base64::FromBase64Error) -> MacaroonError {
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