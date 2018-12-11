//! This module provides utility traits and wrappers for symmetric block ciphers
//! and cryptographically secure hash functions. As we need these for some of
//! our protocols we have implemented a wrapper around the AES implementation 
//! of the `ring` and a wrapper around the Keccak implementation of `tiny-keccak`

use failure::Fallible;
use futures::future::Future;
use generic_array::{ArrayLength, GenericArray};
use std::pin::Pin;

pub mod sha3;

/// Trait for blockciphers to be used in OT. They return a future so we can be
/// more flexible (e.g. using the browser's own cryptographic functions which
/// only work with promises)
pub trait SymmetricCryptoProvider<E>
where
    E: ArrayLength<u8>,
{
    fn encrypt(self, key: GenericArray<u8, E>, data: Vec<u8>) -> Pin<Box<Future<Output = Fallible<Vec<u8>>> + Send>>;
    fn decrypt(self, key: GenericArray<u8, E>, data: Vec<u8>) -> Pin<Box<Future<Output = Fallible<Vec<u8>>> + Send>>;
}


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
/// As a general, fits-most implementation, a wrapper around tiny-keccaks Keccak implementation is provided.
pub trait ArbitraryDigest {
    fn input(&mut self, data: &[u8]);
    fn result(self, output_size: usize) -> Vec<u8>;
}
