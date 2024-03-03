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
