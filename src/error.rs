use std::str;

#[derive(Debug)]
pub enum Error {
    HashFailed,
    NotUTF8(str::Utf8Error),
}