extern crate digest;
extern crate ot;
extern crate rand;
extern crate sha3;

use rand::OsRng;
use ot::base_ot::{BaseOTSender, BaseOTReceiver};
use ot::base_ot::chou::{ChouOrlandiOTReceiver, ChouOrlandiOTSender};
use std::net::TcpListener;
use std::net::TcpStream;
use std::thread;
use sha3::Sha3_256;
use ot::crypto::*;

pub fn main() {
    let n = 5;
    let l = 4;
    let c: u64 = 2;
    let server = thread::spawn(move || {
        let vals: Vec<&[u8]> = vec![b"haus", b"baum", b"welt", b"wort", b"geld"];
        println!("Selected Value: {}", std::str::from_utf8(vals[c as usize]).unwrap());
        assert_eq!(vals.len(),n);
        for val in &vals {
            assert_eq!(val.len(), l);
        }
        let mut ot = ChouOrlandiOTSender::new(
            TcpListener::bind("127.0.0.1:1236")
                .unwrap()
                .accept()
                .unwrap()
                .0,
            Sha3_256::default(),
            DummySymmetric::default(),
            &mut OsRng::new().unwrap(),
        ).unwrap();
        ot.send(vals).unwrap()
    });
    let client = thread::spawn(move || {
        let mut ot = ChouOrlandiOTReceiver::new(
            TcpStream::connect("127.0.0.1:1236").unwrap(),
            Sha3_256::default(),
            DummySymmetric::default(),
            OsRng::new().unwrap(),
        ).unwrap();
        ot.receive(4, n, l).unwrap()
    });
    let _ = server.join().unwrap();
    let result = client.join().unwrap();
    //assert_eq!(result, b"welt");
    println!("Got value: {} for index {}", std::str::from_utf8(&result).unwrap(), c);
}
