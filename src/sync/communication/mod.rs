//! This module provides utility traits and wrappers
//! for basic communication needed by our protocols.
//! While simple TCP and Websocket (courtesy of tungestenite)
//! implementations of these traits are provided it should
//! be trivial to implement them for other means of communications.
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

pub trait GetConn<C: BinarySend + BinaryReceive> {
    fn get_conn(self) -> C;
}
