pub mod macaroon_builder;
pub mod v1;
pub mod v2;
pub mod v2json;

pub enum Format {
    V1,
    V2,
    V2JSON,
}
