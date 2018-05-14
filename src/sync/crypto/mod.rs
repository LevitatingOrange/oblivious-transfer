use errors::*;
use generic_array::{ArrayLength, GenericArray};
pub mod aes;
pub mod dummy;
pub mod sodium;

// TODO: is this a good interface? should there maybe be only one trait?

/// Trait for blockciphers to be used in OT
pub trait SymmetricEncryptor<E>
where
    E: ArrayLength<u8>,
{
    fn encrypt(&mut self, key: &GenericArray<u8, E>, data: Vec<u8>) -> Result<Vec<u8>>;
}

pub trait SymmetricDecryptor<E>
where
    E: ArrayLength<u8>,
{
    fn decrypt(&mut self, key: &GenericArray<u8, E>, data: Vec<u8>) -> Result<Vec<u8>>;
}
