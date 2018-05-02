use errors::*;
use std::vec::Vec;

pub mod corrupted;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod tcp;
pub mod websockets;

pub trait BinarySend {
    fn send(&mut self, data: &[u8]) -> Result<()>;
}

pub trait BinaryReceive {
    fn receive(&mut self) -> Result<Vec<u8>>;
}
