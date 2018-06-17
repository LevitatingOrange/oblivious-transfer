//! # OT extensions
//!
//! With a set of standard OT transfers one can transfer much more data
//! without using expensive public-key-cryptography.
//! While BaseOT implements 1-out-of-n OT, this implements n 1-out-of-2 OTs
//! because that's how most OT extension protocols work.
//! It is trivial to implement 1-out-of-n OT with n 1-out-of-2 OTs.
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
