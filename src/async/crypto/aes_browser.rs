use super::{SymmetricDecryptor, SymmetricEncryptor};
use generic_array::{typenum::U32, GenericArray};
use stdweb::js;
use stdweb::web::{TypedArray, ArrayBuffer};
use futures::prelude::*;
use errors::*;

pub struct WasmAesCryptoProvider();


impl SymmetricEncryptor<U32> for WasmAesCryptoProvider {
    fn encrypt(&mut self, key: &GenericArray<u8, U32>, data: Vec<u8>) -> Box<Future<Item=Vec<u8>, Error=Error>> {
        let arr = TypedArray::from(data.as_slice()).buffer();

    }
}

impl SymmetricDecryptor<U32> for WasmAesCryptoProvider {
    fn decrypt(&mut self, key: &GenericArray<u8, U32>, data: Vec<u8>) -> Box<Future<Item=Vec<u8>, Error=Error>> {
        let arr = TypedArray::from(data.as_slice()).buffer();
    }
}


