use generic_array::{GenericArray, typenum::U32};
use rust_sodium::crypto::stream;

use super::{SymmetricDecryptor, SymmetricEncryptor};

#[derive(Default)]
/// Wrapper around the rust-sodium library
pub struct SodiumCryptoProvider();

impl SymmetricEncryptor<U32> for SodiumCryptoProvider {
    fn encrypt(&mut self, key: GenericArray<u8, U32>, data: &mut [u8]) {
        // this is save because the type GenericArray<u8, U32> gurantees
        // its 32 byte long
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
        // this is save because the type GenericArray<u8, U32> gurantees
        // its 32 byte long
        let mut a_key: [u8; 32] = Default::default();
        a_key.copy_from_slice(&key);
        // TODO: is a constant nonce really ok here? It should be because each
        // key is different.
        let nonce = stream::Nonce([0; 24]);
        stream::stream_xor_inplace(data, &nonce, &stream::Key(a_key));
    }
}
