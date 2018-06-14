#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod websockets;
// TODO consider rtc?!

use futures::Future;
use ::errors::*;
use std::sync::{Arc, Mutex};

pub trait BinarySend {
    fn send(&self, data: Vec<u8>) -> Box<Future<Item = (Arc<Mutex<Self>>), Error=Error>>;
}

pub trait BinaryReceive {
    fn receive(&self) -> Box<Future<Item = (Arc<Mutex<Self>>, Vec<u8>), Error=Error>>;
}

pub trait GetConn<C: BinarySend + BinaryReceive> {
    fn get_conn(self) -> C;
}
