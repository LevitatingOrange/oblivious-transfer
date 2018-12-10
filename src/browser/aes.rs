use crate::crypto::SymmetricCryptoProvider;
use failure::{Fallible, Error};
use generic_array::{typenum::U32, GenericArray};

use stdweb::web::{ArrayBuffer, TypedArray};
use stdweb::unstable::TryInto;
use stdweb::*;
use stdweb::PromiseFuture;
use futures::prelude::*;
use futures::future::{Map, Ready};
use stdweb::web::error::Error as WebError;

use std::pin::Pin;

#[derive(Default, Clone, Copy)]
pub struct AesCryptoProvider();

impl AesCryptoProvider {
    async fn encrypt_inner(self, key: GenericArray<u8, U32>, data: Vec<u8>) -> Result<Vec<u8>, WebError> {
        let arr_key = TypedArray::from(key.as_slice()).buffer();
        let arr_data = TypedArray::from(data.as_slice()).buffer();
        let nonce: [u8; 12] = Default::default();
        let tarr: TypedArray<u8> = TypedArray::from(&nonce[..]);
        let arr_nonce = tarr.buffer();

        let future: PromiseFuture<Vec<u8>> = js! {
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
        }.try_into().unwrap();
        await!(future)
    }

    async fn decrypt_inner(self, key: GenericArray<u8, U32>, data: Vec<u8>) -> Result<Vec<u8>, WebError> {
        let arr_key = TypedArray::from(key.as_slice()).buffer();
        let arr_data = TypedArray::from(data.as_slice()).buffer();
        let nonce: [u8; 12] = Default::default();
        let tarr: TypedArray<u8> = TypedArray::from(&nonce[..]);
        let arr_nonce = tarr.buffer();

        let future: PromiseFuture<Vec<u8>> = js! {
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
                console.log(err);
            });
            return result;
        }.try_into().unwrap();
        await!(future)
        // future.into_future().map(|arr| {
        //     let tarr: TypedArray<u8> = TypedArray::from(arr);
        //     tarr.to_vec()
        // })
    }
}

impl SymmetricCryptoProvider<U32> for AesCryptoProvider {
    //type CryptReturn = Future<Output = Vec<u8>>;

    fn encrypt(self, key: GenericArray<u8, U32>, data: Vec<u8>) -> Pin<Box<Future<Output = Fallible<Vec<u8>>>>> {
        self.encrypt_inner(key, data).map_err(|e| Error::from(e)).boxed()
    }
    fn decrypt(self, key: GenericArray<u8, U32>, data: Vec<u8>) -> Pin<Box<Future<Output = Fallible<Vec<u8>>>>> {
        self.decrypt_inner(key, data).map_err(|e| Error::from(e)).boxed()
    }
}
