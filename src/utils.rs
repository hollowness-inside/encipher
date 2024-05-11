/// Pads a message to the nearest multiple of the block size.
///
/// This function takes a slice of bytes (`bytes`) and a block size (`block_size`) as input.
/// It returns a new vector containing the original bytes padded with the value of the remaining
/// space in the last block.
///
/// If the length of the input `bytes` is already a multiple of the `block_size`, the original
/// `bytes` are returned without modification.
///
pub(crate) fn pad_message(bytes: &[u8], block_size: usize) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    let len = bytes.len();

    if len % block_size == 0 {
        bytes.extend(vec![0; block_size]);
        return bytes;
    }

    let pad_len = block_size - (len % block_size);
    let padding = vec![0; pad_len];

    bytes.reserve(pad_len + block_size);

    bytes.extend(padding);
    bytes.extend(vec![0; block_size - 8]);
    bytes.extend(pad_len.to_le_bytes());
    bytes
}

/// Unpads a message that has been padded to a multiple of the block size.
///
/// This function takes a slice of bytes (`bytes`) and a block size (`block_size`) as input.
/// It returns a slice of the original data without the padding.
///
/// If the last byte of the input `bytes` is not a valid padding value (i.e., greater than
/// or equal to the block size or greater than the length of the input), the original `bytes`
/// are returned without modification.
///
/// # Panics
///
/// This function panics if the input `bytes` is empty.
///
pub(crate) fn unpad_message(bytes: &[u8], block_size: usize) -> &[u8] {
    let len = bytes.len();
    let pad_len = {
        let bytes: [u8; 8] = bytes[len - 8..len].try_into().unwrap();
        usize::from_le_bytes(bytes)
    };

    &bytes[0..len - block_size - pad_len]
}

pub(crate) fn marshal_bytes(bytes: &Vec<Vec<u8>>) -> Vec<u8> {
    let byte_length = bytes.iter().fold(0, |acc, e| acc + e.len());
    let mut result = Vec::with_capacity(byte_length + bytes.len() * 8);

    for b in bytes {
        let len = b.len() as u64;
        result.extend(len.to_be_bytes());
        result.extend(b);
    }

    result
}

pub(crate) fn unmarshal_bytes(raw_bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut result = Vec::with_capacity(raw_bytes.len());

    let mut offset = 0;
    while offset < raw_bytes.len() {
        let len = u64::from_be_bytes(raw_bytes[offset..offset + 8].try_into().unwrap()) as usize;
        offset += 8;

        let bytes = raw_bytes[offset..offset + len].to_vec();
        result.push(bytes)
    }

    result
}
