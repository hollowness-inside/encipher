#[derive(Debug)]
pub enum Error {
    SmallKey
}

pub type Result<T> = std::result::Result<T, Error>;
