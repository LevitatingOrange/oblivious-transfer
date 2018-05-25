use generic_array::{ArrayLength, GenericArray};

pub mod sha3;

/// A simple trait to generalize hashing functions used by this library.
/// It is very similiar to the trait from the crate digest but customized to fit this library's needs.
/// One can use any hash function to initialize the BaseOT and OTExtensions though special care must be taken
/// when selecting one as any security flaw will transitively harm the security of the oblivious transfer.
///
/// As a general, fits-most implementation, a wrapper around tiny-keccaks SHA3 implementation is provided.
pub trait Digest {
    type OutputSize: ArrayLength<u8>;
    fn input(&mut self, data: &[u8]);
    fn result(self) -> GenericArray<u8, Self::OutputSize>;
}

/// Used for ot extensions, this trait generalizes variable-length hashing functions.
///
/// As a general, fits-most implementation, a wrapper asround tiny-keccaks Keccak implementation is provided.
pub trait ArbitraryDigest {
    fn input(&mut self, data: &[u8]);
    fn result(self, output_size: usize) -> Vec<u8>;
}
