use generic_array::{ArrayLength, GenericArray, typenum::U32, typenum::Integer};
use rust_sodium::crypto::stream;

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

#[derive(Default)]
/// Wrapper around the rust-sodium library
pub struct SodiumCryptoProvider();


impl SymmetricEncryptor<U32> for SodiumCryptoProvider {
    fn encrypt(&mut self, key: GenericArray<u8, U32>, data: &mut [u8]) {
        let mut a_key: [u8; 32] = Default::default();
        a_key.copy_from_slice(&key); 
        // TODO: is a constant nonce really ok here? It should be because each 
        // key is different.
        let nonce = stream::Nonce([0; 24]);
        stream::stream_xor_inplace(data, &nonce, &stream::Key(a_key));
    }
}

impl SymmetricDecryptor<U32> for SodiumCryptoProvider {
    fn decrypt(&mut self, key: GenericArray<u8, U32>, data: &mut [u8]) {
        let mut a_key: [u8; 32] = Default::default();
        a_key.copy_from_slice(&key); 
        // TODO: is a constant nonce really ok here? It should be because each 
        // key is different.
        let nonce = stream::Nonce([0; 24]);
        stream::stream_xor_inplace(data, &nonce, &stream::Key(a_key));
    }
}

// impl<E: ArrayLength<u8>> SymmetricDecryptor<E> for SodiumCryptoProvider {
//     fn decrypt(&mut self, key: GenericArray<u8, E>, data: &mut [u8]) {
//         assert!(key.len() == 256);
//         stream::stream_xor_inplace(data, [0; 24], &stream::Key(key));
//     }
// }