use ibig::UBig;

/// A container for encrypted message.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Message {
    /// The type of the message content.
    pub content_type: ContentType,

    /// The actual encrypted content.
    pub content: Content,
}

/// Different formats for encrypted message content depending on the chosen algorithm.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Content {
    /// RSA encryption content containing the chunk size and encrypted message blocks.
    Rsa(usize, Vec<UBig>),

    /// ElGamal encryption content containing the chunk size and ciphertext pairs.
    ElGamal(usize, Vec<[UBig; 2]>),

    /// Rabin encryption content containing the single Rabin ciphertext.
    Rabin(UBig),
}

/// Supported content types for messages.
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ContentType {
    Text,
    Bytes,
}
