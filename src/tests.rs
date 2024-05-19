use crate::utils::{marshal_bytes, pad_message, unmarshal_bytes, unpad_message};

#[test]
fn test_padding_1() {
    let m = [5; 16];

    let a = pad_message(&m, 16);
    println!("{a:?} {}", a.len());

    let b = unpad_message(&a, 16);
    println!("{b:?} {}", b.len());

    assert_eq!(m, b);
}

#[test]
fn test_padding_2() {
    let m = [255; 8];

    let a = pad_message(&m, 16);
    println!("{a:?} {}", a.len());

    let b = unpad_message(&a, 16);
    println!("{b:?} {}", b.len());

    assert_eq!(m, b);
}

#[test]
fn test_marshal_unmarshal() {
    const MESSAGE: [u8; 432] = *b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id";
    let chunks: Vec<Vec<u8>> = MESSAGE.chunks(64).map(|chunk| chunk.to_vec()).collect();

    let marshalled = marshal_bytes(&chunks);
    let unmarshalled: Vec<u8> = unmarshal_bytes(&marshalled).into_iter().flatten().collect();

    assert_eq!(MESSAGE, unmarshalled.as_slice());
}
