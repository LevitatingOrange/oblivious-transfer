//! This module provides utility traits and wrappers
//! for basic communication needed by our protocols.
//! As the async part of this library only supports web assembly
//! at the moment, a wrapper around the browser implementation
//! of websockets is given.

pub mod websockets;
// TODO consider rtc?!

use errors::*;
use futures_core::Future;
use std::sync::{Arc, Mutex};

pub trait BinarySend {
    fn send(&self, data: Vec<u8>) -> Box<Future<Item = (Arc<Mutex<Self>>), Error = Error>>;
}

pub trait BinaryReceive {
    fn receive(&self) -> Box<Future<Item = (Arc<Mutex<Self>>, Vec<u8>), Error = Error>>;
}

pub trait GetConn<C: BinarySend + BinaryReceive> {
    fn get_conn(self) -> Arc<Mutex<C>>;
}
