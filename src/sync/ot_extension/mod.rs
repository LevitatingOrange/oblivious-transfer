//! # OT extensions
//! 
//! With a set of standard OT transfers one can transfer much more data 
//! without using expensive public-key-cryptography.
use bit_vec::BitVec;
use errors::*;

pub mod alsz;
pub mod iknp;

/// This is the base trait for sending all ot-extension protocols in this library implement.
pub trait ExtendedOTSender {
    fn send(self, values: Vec<(&[u8], &[u8])>) -> Result<()>;
}

/// This is the base trait for receiving all ot-extension protocols in this library implement.
pub trait ExtendedOTReceiver {
    fn receive(self, choice_bits: BitVec) -> Result<Vec<Vec<u8>>>;
}
