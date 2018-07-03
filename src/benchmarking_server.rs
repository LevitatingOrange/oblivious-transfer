/// used to allow benchmarking
extern crate ot;
extern crate rand;
extern crate byte_tools;

//extern crate tungstenite;

use ot::common::digest::sha3::SHA3_256;
use ot::common::util::{generate_random_choices, generate_random_string_pairs};
use ot::sync::base_ot::chou::{ChouOrlandiOTReceiver, ChouOrlandiOTSender};
use ot::sync::base_ot::{BaseOTReceiver, BaseOTSender};
use ot::sync::communication::{BinaryReceive, BinarySend, GetConn};
use ot::sync::crypto::aes::AesCryptoProvider;
use ot::sync::ot_extension::iknp::{IKNPExtendedOTReceiver, IKNPExtendedOTSender};
use ot::sync::ot_extension::{ExtendedOTReceiver, ExtendedOTSender};
use rand::distributions::range::Range;
use rand::Rng;
use rand::{ChaChaRng, FromEntropy};
use std::net::TcpListener;
use std::thread::spawn;
use std::time::Instant;
// use tungstenite::handshake::server::Request;
// use tungstenite::server::accept_hdr;

use byte_tools::read_u64_be;

use std::env::args;

fn main() {
    //let args = args();
    //assert_eq!(args.len(), 1);
    let server = TcpListener::bind("127.0.0.1:8123").unwrap();
    for stream in server.incoming() {
        // let callback = |req: &Request| {
        //     println!("Received a new ws handshake");
        //     println!("The request's path is: {}", req.path);
        //     println!("The request's headers are:");
        //     for &(ref header, _ /* value */) in req.headers.iter() {
        //         println!("* {}", header);
        //     }

        //     // TODO: for better example decide based on the subprotocol if you send or receive
        //     let extra_headers = vec![(String::from("Sec-WebSocket-Protocol"), String::from("ot"))];
        //     Ok(Some(extra_headers))
        // };
        spawn(move || {
            //let values = generate_random_string_pairs(VALUE_LENGTH, VALUE_COUNT);
            //println!("Generated values: {:?}", values);

            //let stream = accept_hdr(stream.unwrap(), callback).unwrap();
            let mut stream = stream.unwrap();
            let comm_switch = String::from_utf8(stream.receive().unwrap()).unwrap();
            if &comm_switch == "receive" {
                let bytes = stream.receive().unwrap();
                let n = read_u64_be(&bytes) as usize;

                //println!("Bytes: {:?}", bytes);

                //println!("Length: {}", n);

                let mut rng = ChaChaRng::from_entropy();
                let dist = Range::new(0, n);
                let choice = rng.sample(dist);

                //println!("Generated random index: {:?}", choice);

                //println!("Creating BaseOT receiver...");
                let mut now = Instant::now();
                let mut ot_recv = ChouOrlandiOTReceiver::new(
                    stream,
                    SHA3_256::default(),
                    AesCryptoProvider::default(),
                    rng.clone(),
                ).unwrap();
                //println!("chou ot receiver creation took {:?}", now.elapsed());
                now = Instant::now();
                let values = ot_recv.receive(choice, n).unwrap();
                //println!("Received values: {:?}", values);
                //println!("OT receive took {:?}", now.elapsed());
            } else {
                unimplemented!();
            }

            // println!("Creating BaseOT receiver...");
            // let mut now = Instant::now();
            // let ot_recv = ChouOrlandiOTReceiver::new(
            //     stream.unwrap(),
            //     SHA3_256::default(),
            //     AesCryptoProvider::default(),
            //     rng.clone(),
            // ).unwrap();
            // println!("chou ot receiver creation took {:?}", now.elapsed());
            // println!("Creating OTExtension sender...");
            // now = Instant::now();
            // let mut ot_ext_send =
            //     IKNPExtendedOTSender::new(SHA3_256::default(), ot_recv, rng.clone(), SECURITY_PARAM)
            //         .unwrap();
            // println!("IKNP sender creation took {:?}", now.elapsed());
            // println!("Sending values...");
            // now = Instant::now();
            // let values: Vec<(&[u8], &[u8])> = values
            //     .iter()
            //     .map(|(s1, s2)| (s1.as_bytes(), s2.as_bytes()))
            //     .collect();
            // ot_ext_send.send(values).unwrap();
            // println!("IKNP send took {:?}", now.elapsed());

            // rng = ChaChaRng::from_entropy();

            // println!("Creating BaseOT sender...");
            // now = Instant::now();
            // let ot_send = ChouOrlandiOTSender::new(
            //     ot_ext_send.get_conn(),
            //     SHA3_256::default(),
            //     AesCryptoProvider::default(),
            //     rng.clone(),
            // ).unwrap();
            // println!("chou ot sender creation took {:?}", now.elapsed());
            // now = Instant::now();
            // let mut ot_ext_recv =
            //     IKNPExtendedOTReceiver::new(SHA3_256::default(), ot_send, rng.clone(), SECURITY_PARAM)
            //         .unwrap();
            // println!("IKNP receiver creation took {:?}", now.elapsed());
            // now = Instant::now();
            // let values = ot_ext_recv.receive(&choice_bits).unwrap();
            // println!("IKNP send took {:?}", now.elapsed());
            // let zipped: Vec<(bool, String)> = choice_bits.iter().zip(values.into_iter().map(|s| String::from_utf8(s).unwrap())).collect();
            // println!("Received values: {:?}", zipped);

            //println!("{:?}", sender.compute_keys(10));
        });
    }
}
