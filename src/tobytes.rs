pub trait ToBytes {
    fn to_bytes(self) -> Vec<u8>;
}

impl<'s> ToBytes for &'s str {
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
