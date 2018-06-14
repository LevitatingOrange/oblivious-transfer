pub mod chou;

use ::errors::*;
use futures::Future;

pub trait BaseOTSender<'a> {
    fn send(self, values: Vec<Vec<u8>>) -> Box<Future<Item=Self, Error=Error> + 'a>;
}

pub trait BaseOTReceiver<'a> {
    fn receive(self, c: usize, n: usize) -> Box<Future<Item = (Vec<u8>, Self), Error = Error> + 'a>;
}