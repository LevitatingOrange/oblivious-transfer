use super::{SymmetricDecryptor, SymmetricEncryptor};
use generic_array::{typenum::U32, GenericArray};
use stdweb::js;

pub struct WasmAesCryptoProvider();


impl SymmetricEncryptor<U32> for WasmAesCryptoProvider {

    fn encrypt(&mut self, key: &GenericArray<u8, U32>, data: &mut [u8]) {
        for i in 0..data.len() {
            data[i] ^= key[i % key.len()];
        }
    }
}

impl SymmetricDecryptor<U32> for WasmAesCryptoProvider {
    fn decrypt(&mut self, key: &GenericArray<u8, U32>, data: &mut [u8]) {
        for i in 0..data.len() {
            data[i] ^= key[i % key.len()];
        }
    }
}


