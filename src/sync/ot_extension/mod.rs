use errors::*;
use smallbitvec::SmallBitVec;

pub mod asharov;

pub trait ExtendedOTSender {
    fn send(&mut self, values: Vec<(&[u8], &[u8])>) -> Result<()>;
}

// TODO make choice_bits a BitVec?
pub trait ExtendedOTReceiver {
    fn receive(&mut self, choice_bits: SmallBitVec) -> Result<Vec<Vec<u8>>>;
}
