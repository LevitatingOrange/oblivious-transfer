use std::vec::Vec;
use std::error;
use std::fmt;
use std::io;

pub mod dummy;

#[derive(Debug)]
pub enum Error {
    Connection(io::Error),
    IndexOutOfRange
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Connection(ref e) => e.fmt(f),
            Error::IndexOutOfRange => write!(f, "index out of range")
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Connection(ref e) => e.description(),
            Error::IndexOutOfRange => "The selected index is out of bounds"
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Connection(err)
    }
}



pub trait BaseOT<T> {
    fn send(&mut self, values: Vec<T>) -> Result<(), Error>;
    fn receive(&mut self, index: u64) -> Result<T, Error>;   
}