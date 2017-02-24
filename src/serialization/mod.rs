pub mod v1;
pub mod v2;
pub mod v2j;
pub mod macaroon_builder;

pub enum Format {
    V1,
    V2,
    V2J,
}
