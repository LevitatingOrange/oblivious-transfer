use super::{SymmetricCrypt};
use failure::{Fallible};
use generic_array::{typenum::U32, GenericArray};
use ring::aead::*;

#[derive(Default)]
pub struct AesCryptoProvider();

impl SymmetricCrypt<U32> for AesCryptoProvider {
    fn encrypt(&mut self, key: &GenericArray<u8, U32>, mut data: Vec<u8>) -> Fallible<Vec<u8>> {
        // we can use a static 0 nonce here, because our always keys differ from message to message (TODO: prove that?!)
        let nonce: [u8; 12] = Default::default();
        let len = data.len() + AES_256_GCM.tag_len();
        data.resize(len, 0);
        //let sealing_key = SealingKey::new(&AES_256_GCM, key).map_err(|e| Error::with_chain(e, "Couldnt create aes-gcm encryption key"))?;
        let sealing_key = SealingKey::new(&AES_256_GCM, key)?;
        seal_in_place(&sealing_key, &nonce, &[], &mut data, AES_256_GCM.tag_len())?;
        Ok(data)
    }

    fn decrypt(&mut self, key: &GenericArray<u8, U32>, mut data: Vec<u8>) -> Fallible<(Vec<u8>)> {
        // we can use a static 0 nonce here, because our always keys differ from message to message (TODO: prove that?!)
        let nonce: [u8; 12] = Default::default();
        let opening_key = OpeningKey::new(&AES_256_GCM, key)?;
        open_in_place(&opening_key, &nonce, &[], 0, &mut data)?;
        let len = data.len() - AES_256_GCM.tag_len();
        data.truncate(len);
        Ok(data)
    }
}
