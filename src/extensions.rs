extern crate bit_vec;
extern crate ot;
extern crate rand;

use ot::common::digest::sha3::SHA3_256;
use ot::common::util::{generate_random_choices, generate_random_string_pairs};
use ot::sync::base_ot::chou::{ChouOrlandiOTReceiver, ChouOrlandiOTSender};
use ot::sync::crypto::aes::AesCryptoProvider;
use ot::sync::ot_extension::asharov::{AsharovExtendedOTReceiver, AsharovExtendedOTSender};
use ot::sync::ot_extension::{ExtendedOTReceiver, ExtendedOTSender};
use rand::{ChaChaRng};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Instant};
use rand::FromEntropy;

fn main() {
    let len = 100;
    let n = 5;
    let security_param = 32;

    let choices = generate_random_choices(len);
    let values = generate_random_string_pairs(n, len);

    println!("Choices: {:?}", choices);
    println!("Values: {:?}", values);
    
    let server = thread::spawn(move || {
        let ot_stream = TcpListener::bind("127.0.0.1:1236")
            .unwrap()
            .accept()
            .unwrap()
            .0;
        let rng = ChaChaRng::from_entropy();
        let mut now = Instant::now();
        let ot = ChouOrlandiOTSender::new(
            ot_stream,
            SHA3_256::default(),
            AesCryptoProvider::default(),
            rng.clone(),
        ).unwrap();
        println!("Chou ot sender creation took {:?}", now.elapsed());
        now = Instant::now();
        let ot_ext = AsharovExtendedOTReceiver::new(
            SHA3_256::default(),
            ot,
            rng.clone(),
            security_param,
        ).unwrap();
        println!("Asharaov receiver creation took {:?}", now.elapsed());
        now = Instant::now();
        let values: Vec<String> = ot_ext
            .receive(choices)
            .unwrap()
            .into_iter()
            .map(|v| String::from_utf8(v).unwrap())
            .collect();
        println!("Asharaov receive took {:?}", now.elapsed());
        println!("Received values: {:?}", values);
    });
    let client = thread::spawn(move || {
        let ot_stream = TcpStream::connect("127.0.0.1:1236").unwrap();
        let rng = ChaChaRng::from_entropy();
        let mut now = Instant::now();
        let ot = ChouOrlandiOTReceiver::new(
            ot_stream,
            SHA3_256::default(),
            AesCryptoProvider::default(),
            rng.clone(),
        ).unwrap();
        println!("Chou ot receiver creation took {:?}", now.elapsed());
        now = Instant::now();
        let ot_ext = AsharovExtendedOTSender::new(
            SHA3_256::default(),
            ot,
            rng.clone(),
            security_param,
        ).unwrap();
        println!("Asharaov sender creation took {:?}", now.elapsed());
        now = Instant::now();
        let values: Vec<(&[u8], &[u8])> = values
            .iter()
            .map(|(s1, s2)| (s1.as_bytes(), s2.as_bytes()))
            .collect();
        ot_ext.send(values).unwrap();
        println!("Asharaov send took {:?}", now.elapsed());
    });
    server.join().unwrap();
    client.join().unwrap();
    println!("Finished!");
}
