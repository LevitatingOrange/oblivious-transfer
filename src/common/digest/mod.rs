use generic_array::{ArrayLength, GenericArray};

pub mod sha3;

/// Based off-of the digest trait from RustCrypto but customized to this library's needs
pub trait Digest {
    type OutputSize: ArrayLength<u8>;
    fn input(&mut self, value: &[u8]);
    fn result(self) -> GenericArray<u8, Self::OutputSize>;
}
