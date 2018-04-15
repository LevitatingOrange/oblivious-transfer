extern crate digest;
extern crate ot;
extern crate rand;
extern crate sha3;

use rand::OsRng;
use ot::communication::corrupted::CorruptedChannel;
use ot::base_ot::chou::*;
use std::net::TcpListener;
use std::net::TcpStream;
use std::thread;
use sha3::Sha3_256;

pub fn main() {}
