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
    let len = bytes.len();
    if len % block_size == 0 {
        return bytes.to_vec();
    }

    let pad_len = block_size - (len % block_size);
    let padding = vec![pad_len as u8; pad_len];

    let mut padded_text = bytes.to_vec();
    padded_text.extend_from_slice(&padding);
    padded_text
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
    if let Some(&pad_len) = bytes.last() {
        let pad_len = pad_len as usize;
        let byte_len = bytes.len();

        if pad_len > byte_len {
            return bytes;
        }

        let new_len = byte_len - pad_len;
        if pad_len >= block_size {
            return bytes;
        }

        return &bytes[0..new_len];
    }

    panic!("Empty array");
}
