use generic_array::{ArrayLength, GenericArray};

#[cfg(not(all(target_arch="wasm32", target_os="unknown")))]
pub mod sodium;

// TODO: is this a good interface? should there maybe be only one trait?

/// Trait for blockciphers to be used in OT
pub trait SymmetricEncryptor<E>
where
    E: ArrayLength<u8>,
{
    fn encrypt(&mut self, key: GenericArray<u8, E>, data: &mut [u8]);
}

pub trait SymmetricDecryptor<E>
where
    E: ArrayLength<u8>,
{
    fn decrypt(&mut self, key: GenericArray<u8, E>, data: &mut [u8]);
}

/// Dummy trait that just xors the repeated key onto the data (Vignere encryption).
/// Only here to test, should not be used for anything.

#[derive(Default)]
pub(crate) struct DummyCryptoProvider();

impl<E: ArrayLength<u8>> SymmetricEncryptor<E> for DummyCryptoProvider {
    fn encrypt(&mut self, key: GenericArray<u8, E>, data: &mut [u8]) {
        for i in 0..data.len() {
            data[i] ^= key[i % key.len()];
        }
    }
}

impl<E: ArrayLength<u8>> SymmetricDecryptor<E> for DummyCryptoProvider {
    fn decrypt(&mut self, key: GenericArray<u8, E>, data: &mut [u8]) {
        for i in 0..data.len() {
            data[i] ^= key[i % key.len()];
        }
    }
}