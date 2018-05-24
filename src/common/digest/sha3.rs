use tiny_keccak::Keccak;
use super::Digest;
use generic_array::{ArrayLength, GenericArray, typenum::U32};


/// Wrapper type to implement this library's Digest trait for Sha3-256 (Keccak)
#[derive(Clone)]
pub struct SHA3_256(pub Keccak);

impl Default for SHA3_256 {
    fn default() -> Self {
        SHA3_256(Keccak::new_sha3_256())
    }
}


impl Digest for SHA3_256 {
    type OutputSize = U32;
    fn input(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn result(self) -> GenericArray<u8, Self::OutputSize> {
        let mut arr: GenericArray<u8, Self::OutputSize> = Default::default();
        self.0.finalize(&mut arr);
        return arr;
    }
}