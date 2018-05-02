use errors::*;
use std::vec::Vec;

pub mod dummy;
pub mod chou_async;

pub trait BaseOTSender {
    fn send(&mut self, values: Vec<&[u8]>) -> Result<()>;
}

// TODO: is this interface good?!
// TODO: should we specify the length as it is
// transmitted in clear and could be altered
// either encrypt it or specify l here which we compare to
pub trait BaseOTReceiver {
    fn receive(&mut self, index: u64, n: usize) -> Result<Vec<u8>>;
}
