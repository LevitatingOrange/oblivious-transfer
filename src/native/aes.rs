use crate::crypto::SymmetricCryptoProvider;
use failure::{Fallible};
use futures::future::{ready, Ready};
use futures::prelude::*;
use generic_array::{typenum::U32, GenericArray};
use ring::aead::*;
use std::pin::Pin;

/// Implementation of the CryptoTrait for native environments. It wraps the AES
/// functions of the ring library.
#[derive(Default, Clone, Copy)]
pub struct AesCryptoProvider();

impl AesCryptoProvider {
    fn encrypt_inner(self, key: GenericArray<u8, U32>, mut data: Vec<u8>) -> Fallible<Vec<u8>> {
        // we can use a static 0 nonce here, because our always keys differ from message to message (TODO: prove that?!)
        let nonce: [u8; 12] = Default::default();
        let len = data.len() + AES_256_GCM.tag_len();
        data.resize(len, 0);
        //let sealing_key = SealingKey::new(&AES_256_GCM, key).map_err(|e| Error::with_chain(e, "Couldnt create aes-gcm encryption key"))?;
        let sealing_key = SealingKey::new(&AES_256_GCM, &key)?;
        seal_in_place(&sealing_key, &nonce, &[], &mut data, AES_256_GCM.tag_len())?;
        Ok(data)
    }

    fn decrypt_inner(self, key: GenericArray<u8, U32>, mut data: Vec<u8>) -> Fallible<Vec<u8>> {
        // we can use a static 0 nonce here, because our always keys differ from message to message (TODO: prove that?!)
        let nonce: [u8; 12] = Default::default();
        let opening_key = OpeningKey::new(&AES_256_GCM, &key)?;
        open_in_place(&opening_key, &nonce, &[], 0, &mut data)?;
        let len = data.len() - AES_256_GCM.tag_len();
        data.truncate(len);
        Ok(data)
    }
}

impl SymmetricCryptoProvider<U32> for AesCryptoProvider {
    fn encrypt(self, key: GenericArray<u8, U32>, data: Vec<u8>) -> Pin<Box<Future<Output = Fallible<Vec<u8>>> + Send>> {
        ready(self.encrypt_inner(key, data)).boxed()
    }
    fn decrypt(self, key: GenericArray<u8, U32>, data: Vec<u8>) -> Pin<Box<Future<Output = Fallible<Vec<u8>>> + Send>> {
        ready(self.decrypt_inner(key, data)).boxed()
    }
}
