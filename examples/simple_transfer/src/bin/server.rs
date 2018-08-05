extern crate ot;
extern crate rand;
extern crate tungstenite;

use ot::common::digest::sha3::SHA3_256;
use ot::common::util::{generate_random_choices, generate_random_string_pairs};
use ot::sync::base_ot::chou::{ChouOrlandiOTReceiver, ChouOrlandiOTSender};
use ot::sync::communication::GetConn;
use ot::sync::crypto::aes::AesCryptoProvider;
use ot::sync::ot_extension::iknp::{IKNPExtendedOTReceiver, IKNPExtendedOTSender};
use ot::sync::ot_extension::{ExtendedOTReceiver, ExtendedOTSender};
use rand::{ChaChaRng, FromEntropy};
use std::net::TcpListener;
use std::thread::spawn;
use tungstenite::handshake::server::Request;
use tungstenite::server::accept_hdr;

use std::time::Instant;

fn main() {
    const SECURITY_PARAM: usize = 16;
    const VALUE_COUNT: usize = 1000;
    const VALUE_LENGTH: usize = 64;

    let server = TcpListener::bind("127.0.0.1:3012").unwrap();
    for stream in server.incoming() {
        let callback = |req: &Request| {
            println!("Received a new ws handshake");
            println!("The request's path is: {}", req.path);
            println!("The request's headers are:");
            for &(ref header, _ /* value */) in req.headers.iter() {
                println!("* {}", header);
            }

            // TODO: for better example decide based on the subprotocol if you send or receive
            let extra_headers = vec![(String::from("Sec-WebSocket-Protocol"), String::from("ot"))];
            Ok(Some(extra_headers))
        };
        spawn(move || {
            let values = generate_random_string_pairs(VALUE_LENGTH, VALUE_COUNT);
            let choice_bits = generate_random_choices(VALUE_COUNT);
            //println!("Generated values: {:?}", values);

            let stream = accept_hdr(stream.unwrap(), callback).unwrap();
            let mut rng = ChaChaRng::from_entropy();

            println!("Creating BaseOT receiver...");
            let mut now = Instant::now();
            let ot_recv = ChouOrlandiOTReceiver::new(
                stream,
                SHA3_256::default(),
                AesCryptoProvider::default(),
                rng.clone(),
            ).unwrap();
            println!("chou ot receiver creation took {:?}", now.elapsed());
            println!("Creating OTExtension sender...");
            now = Instant::now();
            let mut ot_ext_send = IKNPExtendedOTSender::new(
                SHA3_256::default(),
                ot_recv,
                rng.clone(),
                SECURITY_PARAM,
            ).unwrap();
            println!("IKNP sender creation took {:?}", now.elapsed());
            println!("Sending values...");
            now = Instant::now();
            let values: Vec<(&[u8], &[u8])> = values
                .iter()
                .map(|(s1, s2)| (s1.as_bytes(), s2.as_bytes()))
                .collect();
            ot_ext_send.send(values).unwrap();
            println!("IKNP send took {:?}", now.elapsed());

            rng = ChaChaRng::from_entropy();

            println!("Creating BaseOT sender...");
            now = Instant::now();
            let ot_send = ChouOrlandiOTSender::new(
                ot_ext_send.get_conn(),
                SHA3_256::default(),
                AesCryptoProvider::default(),
                rng.clone(),
            ).unwrap();
            println!("chou ot sender creation took {:?}", now.elapsed());
            now = Instant::now();
            let mut ot_ext_recv = IKNPExtendedOTReceiver::new(
                SHA3_256::default(),
                ot_send,
                rng.clone(),
                SECURITY_PARAM,
            ).unwrap();
            println!("IKNP receiver creation took {:?}", now.elapsed());
            now = Instant::now();
            let values = ot_ext_recv.receive(&choice_bits).unwrap();
            println!("IKNP send took {:?}", now.elapsed());
            let zipped: Vec<(bool, String)> = choice_bits
                .iter()
                .zip(values.into_iter().map(|s| String::from_utf8(s).unwrap()))
                .collect();
            //println!("Received values: {:?}", zipped);

            //println!("{:?}", sender.compute_keys(10));
        });
    }
}
