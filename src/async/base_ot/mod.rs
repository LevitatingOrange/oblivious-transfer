//! # Base OT
//!
//! Implementations of  1-out-of-n oblivious transfer protocols.
//! As these rely on expensive public-key-cryptography one is advised
//! to compose these with extended OT.
pub mod chou;

use errors::*;
use futures::Future;

pub trait BaseOTSender<'a> {
    // sadly, impl Trait is not available in trait methods, so we have to use a Box here
    fn send(self, values: Vec<Vec<u8>>) -> Box<Future<Item = Self, Error = Error> + 'a>;
}

pub trait BaseOTReceiver<'a> {
    // sadly, impl Trait is not available in trait methods, so we have to use a Box here
    fn receive(self, c: usize, n: usize)
        -> Box<Future<Item = (Vec<u8>, Self), Error = Error> + 'a>;
}
