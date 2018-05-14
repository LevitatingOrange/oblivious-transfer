use super::{SymmetricDecryptor, SymmetricEncryptor};
use errors::*;
use futures::prelude::*;
use generic_array::{typenum::U32, GenericArray};
use stdweb::unstable::TryInto;
use stdweb::web::{ArrayBuffer, TypedArray};
use stdweb::PromiseFuture;
use stdweb::*;

// TODO: add  this to an preloaded js file
// window.crypto = window.crypto || window.msCrypto; //for IE11
// if(window.crypto.webkitSubtle){
//     window.crypto.subtle = window.crypto.webkitSubtle; //for Safari
// }
pub struct WasmAesCryptoProvider();

impl SymmetricEncryptor<U32> for WasmAesCryptoProvider {
    fn encrypt(
        &mut self,
        key: &GenericArray<u8, U32>,
        data: Vec<u8>,
    ) -> Box<Future<Item = Vec<u8>, Error = Error>> {
        let arr_key = TypedArray::from(key.as_slice()).buffer();
        let arr_data = TypedArray::from(data.as_slice()).buffer();
        let future: PromiseFuture<ArrayBuffer> = js! {
            var algorithm = {
                "name": "AES-GCM",
                "iv": new ArrayBuffer(0),
                "tagLength": 16
            };
            var crypto = window.crypto.subtle;
            var result = crypto.importKey(
                "raw",
                @{arr_key},
                algorithm,
                false,
                ["encrypt"]
            ).then(function(key) {
                crypto.encrypt(algorithm, key, @{arr_data})
            });
            return future;
        }.try_into()
            .unwrap();
        Box::new(
            future
                .map(|arr| {
                    let tarr: TypedArray<u8> = TypedArray::from(arr);
                    tarr.to_vec()
                })
                .map_err(|e| Error::with_chain(e, "Couldn't decrypt with aes-gcm")),
        )
    }
}

impl SymmetricDecryptor<U32> for WasmAesCryptoProvider {
    fn decrypt(
        &mut self,
        key: &GenericArray<u8, U32>,
        data: Vec<u8>,
    ) -> Box<Future<Item = Vec<u8>, Error = Error>> {
        let arr_key = TypedArray::from(key.as_slice()).buffer();
        let arr_data = TypedArray::from(data.as_slice()).buffer();
        let future: PromiseFuture<ArrayBuffer> = js! {
            var algorithm = {
                "name": "AES-GCM",
                "iv": new ArrayBuffer(0),
                "tagLength": 16
            };
            var crypto = window.crypto.subtle;
            var result = crypto.importKey(
                "raw",
                @{arr_key},
                algorithm,
                false,
                ["decrypt"]
            ).then(function(key) {
                crypto.decrypt(algorithm, key, @{arr_data})
            });
            return future;
        }.try_into()
            .unwrap();
        Box::new(
            future
                .map(|arr| {
                    let tarr: TypedArray<u8> = TypedArray::from(arr);
                    tarr.to_vec()
                })
                .map_err(|e| Error::with_chain(e, "Couldn't decrypt with aes-gcm")),
        )
    }
}
