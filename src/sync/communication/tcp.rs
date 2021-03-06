use super::{BinaryReceive, BinarySend};
/// simple protocol: data gets it's length prepended and send
use errors::*;
use std::io::{Read, Write};
use std::mem::transmute;
use std::net::TcpStream;
use std::vec::Vec;

// TODO: find alternative for transmute!

impl BinarySend for TcpStream {
    fn send(&mut self, data: &[u8]) -> Result<()> {
        let bytes: [u8; 8] = unsafe { transmute((data.len() as u64).to_be()) };
        self.write_all(&bytes)?;
        self.write_all(data)?;
        self.flush()?;
        Ok(())
    }
}

impl BinaryReceive for TcpStream {
    fn receive(&mut self) -> Result<Vec<u8>> {
        let mut bytes: [u8; 8] = Default::default();
        self.read_exact(&mut bytes)?;
        let len = unsafe { u64::from_be(transmute(bytes)) as usize };
        let mut v = Vec::with_capacity(len);
        v.resize(len, 0);
        self.read_exact(&mut v)?;
        Ok(v)
    }
}
