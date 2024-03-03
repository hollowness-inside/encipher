#[derive(Debug)]
pub enum Error {
    SmallKey,
    IncorrectAlgorithm,
}

pub type Result<T> = std::result::Result<T, Error>;
