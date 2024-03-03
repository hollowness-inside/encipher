use crate::{message::Message, result::Result, typed::TypedContent};

pub trait KeyPair {
    fn generate(bit_length: usize, persistence: usize) -> Self;
    fn encrypt<C: TypedContent>(&self, content: C) -> Result<Message>;
    fn decrypt(&self, message: Message) -> Result<Vec<u8>>;
}
