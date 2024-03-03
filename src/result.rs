#[derive(Debug)]
pub enum Error {
    SmallKey,
    IncorrectAlgorithm,
    MessageNotFound,
}

pub type Result<T> = std::result::Result<T, Error>;
