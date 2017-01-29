use std::str;

#[derive(Debug)]
pub enum MacaroonError {
    HashFailed,
    NotUTF8(str::Utf8Error),
    UnknownSerialization,
    DeserializationError(String),
    BadMacaroon(&'static str),
    KeyError(&'static str),
}