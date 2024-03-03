use crate::message::ContentType;

pub trait TypedContent {
    fn typed(self) -> (ContentType, Vec<u8>);
}

impl<'s> TypedContent for &'s str {
    #[inline]
    fn typed(self) -> (ContentType, Vec<u8>) {
        (ContentType::Text, self.as_bytes().to_vec())
    }
}

impl TypedContent for String {
    #[inline(always)]
    fn typed(self) -> (ContentType, Vec<u8>) {
        self.as_str().typed()
    }
}

impl<'s> TypedContent for &'s [u8] {
    #[inline]
    fn typed(self) -> (ContentType, Vec<u8>) {
        (ContentType::Bytes, self.to_vec())
    }
}

impl TypedContent for Vec<u8> {
    #[inline(always)]
    fn typed(self) -> (ContentType, Vec<u8>) {
        self.as_slice().typed()
    }
}

impl TypedContent for (ContentType, Vec<u8>) {
    #[inline(always)]
    fn typed(self) -> (ContentType, Vec<u8>) {
        self
    }
}
