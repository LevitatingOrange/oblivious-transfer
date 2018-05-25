extern crate bit_vec;
extern crate ot;
extern crate rand;

use ot::common::digest::sha3::SHA3_256;
use ot::common::digest::ArbitraryDigest;
use ot::common::util::{generate_random_choices, generate_random_string_pairs};
use ot::sync::base_ot::chou::{ChouOrlandiOTReceiver, ChouOrlandiOTSender};
use ot::sync::crypto::aes::AesCryptoProvider;
use ot::sync::ot_extension::asharov::{AsharovExtendedOTReceiver, AsharovExtendedOTSender};
use ot::sync::ot_extension::{ExtendedOTReceiver, ExtendedOTSender};
use rand::{ChaChaRng, OsRng, Rng, SeedableRng};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let len = 100;
    let n = 5;
    let security_param = 16;

    let choices = generate_random_choices(len);
    let values = generate_random_string_pairs(n, len);
    let seed: [u32; 8] = OsRng::new().unwrap().gen();

    println!("Choices: {:?}", choices);
    println!("Values: {:?}", values);

    let server = thread::spawn(move || {
        let ot_stream = TcpListener::bind("127.0.0.1:1236")
            .unwrap()
            .accept()
            .unwrap()
            .0;
        let mut now = Instant::now();
        let ot = ChouOrlandiOTSender::new(
            ot_stream,
            SHA3_256::default(),
            AesCryptoProvider::default(),
            &mut ChaChaRng::from_seed(&seed),
        ).unwrap();
        println!("Chou ot sender creation took {:?}", now.elapsed());
        now = Instant::now();
        let ot_ext = AsharovExtendedOTReceiver::new(
            SHA3_256::default(),
            ot,
            ChaChaRng::from_seed(&seed),
            security_param,
        ).unwrap();
        println!("Asharaov receiver creation took {:?}", now.elapsed());
        now = Instant::now();
        // let values: Vec<String> = ot_ext
        //     .receive(choices)
        //     .unwrap()
        //     .into_iter()
        //     .map(|v| String::from_utf8(v).unwrap())
        //     .collect();
        let values: Vec<Vec<u8>> = ot_ext
            .receive(choices)
            .unwrap();
        println!("Asharaov receive took {:?}", now.elapsed());
        println!("Received values: {:?}", values);
    });
    let client = thread::spawn(move || {
        let ot_stream = TcpStream::connect("127.0.0.1:1236").unwrap();
        let mut now = Instant::now();
        let ot = ChouOrlandiOTReceiver::new(
            ot_stream,
            SHA3_256::default(),
            AesCryptoProvider::default(),
            ChaChaRng::from_seed(&seed),
        ).unwrap();
        println!("Chou ot receiver creation took {:?}", now.elapsed());
        now = Instant::now();
        let ot_ext = AsharovExtendedOTSender::new(
            SHA3_256::default(),
            ot,
            ChaChaRng::from_seed(&seed),
            security_param,
        ).unwrap();
        println!("Asharaov sender creation took {:?}", now.elapsed());
        now = Instant::now();
        let values: Vec<(&[u8], &[u8])> = values
            .iter()
            .map(|(s1, s2)| (s1.as_bytes(), s2.as_bytes()))
            .collect();
        println!("Byte values {:?}", values);
        ot_ext.send(values).unwrap();
        println!("Asharaov send took {:?}", now.elapsed());
    });
    server.join().unwrap();
    client.join().unwrap();
    println!("Finished!");
}
