#[derive(Debug)]
pub enum Error {
    /// Indicates that the provided key is smaller than the provided message.
    SmallKey,

    /// Indicates that the message was encrypted with another algorithm.
    IncorrectAlgorithm,

    /// Indicates that the original message could not be found.
    MessageNotFound,

    MathError,
}

pub type Result<T> = std::result::Result<T, Error>;
