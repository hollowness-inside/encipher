/// Marshals a vector of vectors of bytes into a single byte vector.
///
/// Each inner vector represents a chunk of bytes to be marshalled.
/// The resulting byte vector is formatted such that each chunk is prefixed
/// with an 8-byte length field in big-endian format.
///
/// # Arguments
///
/// * `bytes` - A reference to a vector of vectors of bytes to be marshalled.
///
/// # Returns
///
/// A byte vector containing the marshalled bytes.
///
pub(crate) fn marshal_bytes(bytes: &Vec<Vec<u8>>) -> Vec<u8> {
    let byte_length = bytes.iter().fold(0, |acc, e| acc + e.len());
    let mut result = Vec::with_capacity(byte_length + bytes.len() * 8);

    for b in bytes {
        let len = b.len() as u64;
        result.extend(len.to_le_bytes());
        result.extend(b);
    }

    result
}

/// Unmarshals a slice of raw bytes into a vector of vectors of bytes.
///
/// Each inner vector represents a chunk of bytes extracted from the raw byte slice.
/// The input `raw_bytes` slice is expected to be formatted such that each chunk is prefixed
/// with an 8-byte length field in big-endian format.
///
/// # Arguments
///
/// * `raw_bytes` - A slice of raw bytes to be unmarshalled.
///
/// # Returns
///
/// A vector of vectors of bytes, where each inner vector contains a chunk of bytes.
///
pub(crate) fn unmarshal_bytes(raw_bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut result = Vec::with_capacity(raw_bytes.len());

    let mut offset = 0;
    while offset < raw_bytes.len() {
        let len = u64::from_le_bytes(raw_bytes[offset..offset + 8].try_into().unwrap()) as usize;
        offset += 8;

        let bytes = raw_bytes[offset..offset + len].to_vec();
        result.push(bytes);
        offset += len;
    }

    result
}
