use ibig::UBig;

#[derive(Debug)]
pub struct Message {
    pub content_type: ContentType,
    pub content: Content,
}

#[derive(Debug)]
pub enum Content {
    Rsa(usize, Vec<UBig>),
}

#[derive(Debug, PartialEq)]
pub enum ContentType {
    Text,
    Bytes,
}
