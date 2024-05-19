#[derive(Debug)]
pub struct Content {
    pub chunk_size: usize,
    pub data: Vec<u8>,
}

impl Content {
    pub fn new(chunk_size: usize, data: &[u8]) -> Self {
        Self {
            chunk_size,
            data: data.to_vec(),
        }
    }
}

pub trait ToBytes {
    fn to_bytes(self) -> Vec<u8>;
}

/// Trait for types that can be converted to a content type and byte representation.
///
/// This trait defines a single method `typed` which takes the implementing type as `self`
/// and returns a tuple containing the associated `ContentType` and the byte representation
/// of the data as a `Vec<u8>`.
impl<'s> ToBytes for &'s str {
    /// Converts the implementing type to a `Content` tuple.
    ///
    /// This function returns a tuple containing the associated `ContentType` and the
    /// byte representation of the data as a `Vec<u8>`.
    #[inline]
    fn to_bytes(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl ToBytes for String {
    #[inline(always)]
    fn to_bytes(self) -> Vec<u8> {
        self.as_str().to_bytes()
    }
}

impl<'s> ToBytes for &'s [u8] {
    #[inline]
    fn to_bytes(self) -> Vec<u8> {
        self.to_vec()
    }
}

impl ToBytes for Vec<u8> {
    #[inline(always)]
    fn to_bytes(self) -> Vec<u8> {
        self.as_slice().to_bytes()
    }
}
