use generic_array::{ArrayLength, GenericArray};

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod sodium;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod aes_browser;

pub mod dummy;

// TODO: is this a good interface? should there maybe be only one trait?

/// Trait for blockciphers to be used in OT
pub trait SymmetricEncryptor<E>
where
    E: ArrayLength<u8>,
{
    fn encrypt(&mut self, key: &GenericArray<u8, E>, data: &mut [u8]);
}

pub trait SymmetricDecryptor<E>
where
    E: ArrayLength<u8>,
{
    fn decrypt(&mut self, key: &GenericArray<u8, E>, data: &mut [u8]);
}
