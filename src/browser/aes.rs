use crate::crypto::SymmetricCryptoProvider;
use failure::{Fallible, Error};
use generic_array::{typenum::U32, GenericArray};

use stdweb::web::{TypedArray};
use stdweb::unstable::TryInto;
use stdweb::*;
use stdweb::PromiseFuture;
use futures::prelude::*;

use std::pin::Pin;

#[derive(Default, Clone, Copy)]
pub struct AesCryptoProvider();

impl AesCryptoProvider {
    fn encrypt_inner(self, key: GenericArray<u8, U32>, data: Vec<u8>) -> PromiseFuture<Vec<u8>> {
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
        future
    }

    fn decrypt_inner(self, key: GenericArray<u8, U32>, data: Vec<u8>) -> PromiseFuture<Vec<u8>> {
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
        future
        // future.into_future().map(|arr| {
        //     let tarr: TypedArray<u8> = TypedArray::from(arr);
        //     tarr.to_vec()
        // })
    }
}

impl SymmetricCryptoProvider<U32> for AesCryptoProvider {
    //type CryptReturn = Future<Output = Vec<u8>>;

    fn encrypt(self, key: GenericArray<u8, U32>, data: Vec<u8>) -> Pin<Box<Future<Output = Fallible<Vec<u8>>> + Send>> {
        self.encrypt_inner(key, data).map_err(|e| Error::from(e)).boxed()
    }
    fn decrypt(self, key: GenericArray<u8, U32>, data: Vec<u8>) -> Pin<Box<Future<Output = Fallible<Vec<u8>>> + Send>> {
        self.decrypt_inner(key, data).map_err(|e| Error::from(e)).boxed()
    }
}
