use generic_array::{typenum::U32, GenericArray};
use rust_sodium::crypto::stream;

use super::{SymmetricDecryptor, SymmetricEncryptor};
use errors::*;

#[derive(Default)]
/// Wrapper around the rust-sodium library
pub struct SodiumCryptoProvider();

impl SymmetricEncryptor<U32> for SodiumCryptoProvider {
    fn encrypt(&mut self, key: &GenericArray<u8, U32>, mut data: Vec<u8>) -> Result<Vec<u8>> {
        // this is save because the type GenericArray<u8, U32> gurantees
        // its 32 byte long
        let mut a_key: [u8; 32] = Default::default();
        a_key.copy_from_slice(&key);
        // TODO: is a constant nonce really ok here? It should be because each
        // key is different.
        let nonce = stream::Nonce([0; 24]);
        stream::stream_xor_inplace(&mut data, &nonce, &stream::Key(a_key));
        Ok(data)
    }
}

impl SymmetricDecryptor<U32> for SodiumCryptoProvider {
    fn decrypt(&mut self, key: &GenericArray<u8, U32>, mut data: Vec<u8>) -> Result<Vec<u8>> {
        // this is save because the type GenericArray<u8, U32> gurantees
        // its 32 byte long
        let mut a_key: [u8; 32] = Default::default();
        a_key.copy_from_slice(&key);
        // TODO: is a constant nonce really ok here? It should be because each
        // key is different.
        let nonce = stream::Nonce([0; 24]);
        stream::stream_xor_inplace(&mut data, &nonce, &stream::Key(a_key));
        Ok(data)
    }
}
