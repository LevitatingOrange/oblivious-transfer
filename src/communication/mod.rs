use std::io;
use std::mem::transmute;
use std::vec::Vec;
use std::net::TcpStream;
use std::io::{Read, Write};

pub mod corrupted;

pub trait BinarySend {
    fn send(&mut self, data: &[u8]) -> Result<(), io::Error>;
}

pub trait BinaryReceive {
    fn receive(&mut self) -> Result<Vec<u8>, io::Error>;
}

impl BinarySend for TcpStream {
    fn send(&mut self, data: &[u8]) -> Result<(), io::Error> {
        let bytes: [u8; 8] = unsafe { transmute((data.len() as u64).to_be()) };
        self.write(&bytes)?;
        self.write(data)?;
        self.flush()
    }
}

impl BinaryReceive for TcpStream {
    fn receive(&mut self) -> Result<Vec<u8>, io::Error> {
        let mut bytes: [u8; 8] = Default::default();
        self.read_exact(&mut bytes)?;
        let len = unsafe { u64::from_be(transmute(bytes)) as usize };
        let mut v = Vec::with_capacity(len);
        v.resize(len, 0);
        self.read_exact(&mut v)?;
        Ok(v)
    }
}
