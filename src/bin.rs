extern crate ot;
extern crate digest;
extern crate sha3;
extern crate rand;

use rand::OsRng;
use ot::base_ot::chou::*;
use std::net::TcpListener;
use std::net::TcpStream;
use std::thread;
use sha3::Sha3_256;
use digest::Digest;

pub fn main() {
        let server = thread::spawn(move || {
            let mut ot = ChouOrlandiOTSender::new(TcpListener::bind("127.0.0.1:1235").unwrap().accept().unwrap().0, &mut OsRng::new().unwrap()).unwrap();
            ot.compute_keys(10, Sha3_256::default()).unwrap()
        });
        let client = thread::spawn(move || {
            let mut ot = ChouOrlandiOTReceiver::new(TcpStream::connect("127.0.0.1:1235").unwrap(), OsRng::new().unwrap()).unwrap();
            ot.compute_key(2, Sha3_256::default()).unwrap()
        });
        let hashes_sender = server.join().unwrap();
        let hash_receiver = client.join().unwrap();
        
        println!("sender's hashes:");
        for h in hashes_sender {
        println!("{:?}", h);
        }
        println!("receiver's hash:");
        println!("{:?}", hash_receiver);
}