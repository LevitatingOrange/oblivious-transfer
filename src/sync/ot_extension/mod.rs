use bit_vec::BitVec;
use errors::*;

pub mod asharov;

pub trait ExtendedOTSender {
    fn send(self, values: Vec<(&[u8], &[u8])>) -> Result<()>;
}

// TODO make choice_bits a BitVec?
pub trait ExtendedOTReceiver {
    fn receive(self, choice_bits: BitVec) -> Result<Vec<Vec<u8>>>;
}
