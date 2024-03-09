use crate::utils::{pad_message, unpad_message};

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