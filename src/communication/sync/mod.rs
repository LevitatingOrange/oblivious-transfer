use errors::*;
use std::vec::Vec;

pub mod corrupted;
pub mod tcp;
pub mod websockets;

pub trait BinarySend {
    fn send(&mut self, data: &[u8]) -> Result<()>;
}

pub trait BinaryReceive {
    fn receive(&mut self) -> Result<Vec<u8>>;
}
