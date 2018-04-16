use std::io;
use std::vec::Vec;

pub mod corrupted;
pub mod tcp;

pub trait BinarySend {
    fn send(&mut self, data: &[u8]) -> Result<(), io::Error>;
}

pub trait BinaryReceive {
    fn receive(&mut self) -> Result<Vec<u8>, io::Error>;
}
