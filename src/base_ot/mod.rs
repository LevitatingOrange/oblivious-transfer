use std::vec::Vec;
use std::error;
use std::fmt;
use std::io;

pub mod dummy;
pub mod chou;

#[derive(Debug)]
pub enum Error {
    PointError, 
    Connection(io::Error),
    IndexOutOfRange
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::PointError => write!(f, "received point is invalid"),
            Error::Connection(ref e) => e.fmt(f),
            Error::IndexOutOfRange => write!(f, "index out of range")
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::PointError => "This is caused by corrupted communication channel",
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



pub trait BaseOTSender<T> {
    fn send(&mut self, values: Vec<T>) -> Result<(), Error>;
}

pub trait BaseOTReceiver<T> {
    fn receive(&mut self, index: u64) -> Result<T, Error>;   
}