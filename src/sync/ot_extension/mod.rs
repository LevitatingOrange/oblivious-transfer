use bit_vec::BitVec;
use errors::*;

pub mod alsz;
pub mod iknp;

pub trait ExtendedOTSender {
    fn send(self, values: Vec<(&[u8], &[u8])>) -> Result<()>;
}

pub trait ExtendedOTReceiver {
    fn receive(self, choice_bits: BitVec) -> Result<Vec<Vec<u8>>>;
}
