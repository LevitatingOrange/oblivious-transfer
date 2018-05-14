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
#[derive(Default)]
pub struct AesCryptoProvider();

impl SymmetricEncryptor<U32> for AesCryptoProvider {
    fn encrypt(
        &mut self,
        key: &GenericArray<u8, U32>,
        data: Vec<u8>,
    ) -> Box<Future<Item = Vec<u8>, Error = Error>> {
        let arr_key = TypedArray::from(key.as_slice()).buffer();
        let arr_data = TypedArray::from(data.as_slice()).buffer();
        let nonce: [u8; 12] = Default::default();
        let tarr: TypedArray<u8> = TypedArray::from(&nonce[..]);
        let arr_nonce = tarr.buffer();
        let future: Result<PromiseFuture<ArrayBuffer>> = js! {
            var algorithm = {
                "name": "AES-GCM",
                "iv": @{arr_nonce},
                "tagLength": 128,
            };
            var crypto = window.crypto.subtle;
            var result = crypto.importKey(
                "raw",
                @{arr_key},
                algorithm,
                false,
                ["encrypt"]
            ).then(function(key) {
                return crypto.encrypt(algorithm, key, @{arr_data});
            }).catch(function(err) {
                console.log(err);
            });
            return result;
        }.try_into()
            .chain_err(|| "encryption failed");
        Box::new(
            future
                .into_future()
                .and_then(|f| f.map_err(|e| Error::with_chain(e, "Couldn't encrypt with aes-gcm")))
                .map(|arr| {
                    let tarr: TypedArray<u8> = TypedArray::from(arr);
                    tarr.to_vec()
                }),
        )
    }
}

impl SymmetricDecryptor<U32> for AesCryptoProvider {
    fn decrypt(
        &mut self,
        key: &GenericArray<u8, U32>,
        data: Vec<u8>,
    ) -> Box<Future<Item = Vec<u8>, Error = Error>> {
        let arr_key = TypedArray::from(key.as_slice()).buffer();
        let arr_data = TypedArray::from(data.as_slice()).buffer();
        let nonce: [u8; 12] = Default::default();
        let tarr: TypedArray<u8> = TypedArray::from(&nonce[..]);
        let arr_nonce = tarr.buffer();
        let future: Result<PromiseFuture<ArrayBuffer>> = js! {
            var algorithm = {
                "name": "AES-GCM",
                "iv": @{arr_nonce},
                "tagLength": 128,
            };
            var crypto = window.crypto.subtle;
            var result = crypto.importKey(
                "raw",
                @{arr_key},
                algorithm,
                false,
                ["decrypt"]
            ).then(function(key) {
                return crypto.decrypt(algorithm, key, @{arr_data});
            }).catch(function(err) {
                console.error(err);
            });
            return result;
        }.try_into()
            .chain_err(|| "decryption failed");
        Box::new(
            future
                .into_future()
                .and_then(|f| f.map_err(|e| Error::with_chain(e, "Couldn't decrypt with aes-gcm")))
                .map(|arr| {
                    let tarr: TypedArray<u8> = TypedArray::from(arr);
                    tarr.to_vec()
                }),
        )
    }
}
