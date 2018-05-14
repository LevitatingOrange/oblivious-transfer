use errors::*;
use futures::Future;
use generic_array::{ArrayLength, GenericArray};
pub mod aes_browser;
pub mod dummy;

// TODO: is this a good interface? should there maybe be only one trait?
// TODO: wait for Rust allowing impl Trait in traits, then remove all Boxes (should be worked on right now)

/// Trait for blockciphers to be used in OT
pub trait SymmetricEncryptor<E>
where
    E: ArrayLength<u8>,
{
    fn encrypt(
        &mut self,
        key: &GenericArray<u8, E>,
        data: Vec<u8>,
    ) -> Box<Future<Item = Vec<u8>, Error = Error>>;
}

pub trait SymmetricDecryptor<E>
where
    E: ArrayLength<u8>,
{
    fn decrypt(
        &mut self,
        key: &GenericArray<u8, E>,
        data: Vec<u8>,
    ) -> Box<Future<Item = Vec<u8>, Error = Error>>;
}
