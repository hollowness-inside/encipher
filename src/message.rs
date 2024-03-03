use ibig::UBig;

#[derive(Debug)]
pub struct Message {
    pub content_type: ContentType,
    pub content: Content,
}

#[derive(Debug)]
pub enum Content {
    Rsa(usize, Vec<UBig>),
    ElGamal(usize, Vec<[UBig; 2]>),
    Rabin(UBig),
}

#[derive(Debug, PartialEq)]
pub enum ContentType {
    Text,
    Bytes,
}
