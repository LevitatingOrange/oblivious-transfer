/// Dummy trait that just xors the repeated key onto the data (Vignere encryption).
/// Only here to test, should not be used for anything.
use super::{SymmetricDecryptor, SymmetricEncryptor};
use errors::*;
use generic_array::{ArrayLength, GenericArray};

#[derive(Default)]
pub struct DummyCryptoProvider();

impl<E: ArrayLength<u8>> SymmetricEncryptor<E> for DummyCryptoProvider {
    fn encrypt(&mut self, key: &GenericArray<u8, E>, mut data: Vec<u8>) -> Result<Vec<u8>> {
        for i in 0..data.len() {
            data[i] ^= key[i % key.len()];
        }
        Ok(data)
    }
}

impl<E: ArrayLength<u8>> SymmetricDecryptor<E> for DummyCryptoProvider {
    fn decrypt(&mut self, key: &GenericArray<u8, E>, mut data: Vec<u8>) -> Result<Vec<u8>> {
        for i in 0..data.len() {
            data[i] ^= key[i % key.len()];
        }
        Ok(data)
    }
}
