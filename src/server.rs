// #[macro_use]
// extern crate structopt;
#[macro_use]
extern crate ot;
extern crate rand;
extern crate tungstenite;

use ot::common::digest::sha3::SHA3_256;
use ot::common::util::{generate_random_string_pairs, generate_random_choices};
use ot::sync::base_ot::chou::{ChouOrlandiOTReceiver, ChouOrlandiOTSender};
use ot::sync::base_ot::{BaseOTReceiver, BaseOTSender};
use ot::sync::crypto::aes::AesCryptoProvider;
use ot::sync::communication::GetConn;
use ot::sync::ot_extension::iknp::{IKNPExtendedOTReceiver, IKNPExtendedOTSender};
use ot::sync::ot_extension::{ExtendedOTReceiver, ExtendedOTSender};
use rand::{ChaChaRng, FromEntropy};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread::spawn;
// use structopt::StructOpt;
use tungstenite::handshake::server::Request;
use tungstenite::server::accept_hdr;
use tungstenite::Message;

use std::time::Instant;

fn main() {
    const SECURITY_PARAM: usize = 16;
    const VALUE_COUNT: usize = 10;
    const VALUE_LENGTH: usize = 5;

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
            println!("Generated values: {:?}", values);

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
            let mut ot_ext_send =
                IKNPExtendedOTSender::new(SHA3_256::default(), ot_recv, rng.clone(), SECURITY_PARAM)
                    .unwrap();
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
            let mut ot_ext_recv =
                IKNPExtendedOTReceiver::new(SHA3_256::default(), ot_send, rng.clone(), SECURITY_PARAM)
                    .unwrap();
            println!("IKNP receiver creation took {:?}", now.elapsed());
            now = Instant::now();
            let values = ot_ext_recv.receive(&choice_bits).unwrap();
            println!("IKNP send took {:?}", now.elapsed());
            let zipped: Vec<(bool, String)> = choice_bits.iter().zip(values.into_iter().map(|s| String::from_utf8(s).unwrap())).collect();
            println!("Received values: {:?}", zipped);

            //println!("{:?}", sender.compute_keys(10));
        });
    }
}

// #[derive(StructOpt, Debug)]
// #[structopt(name = "ot")]
// struct Opt {
//     #[structopt(name = "address", help = "Address the server should listen on")]
//     address: String,
//     #[structopt(name = "index", help = "Index of received value")]
//     index: usize,
//     #[structopt(name = "length", help = "Length of received values")]
//     length: usize,
//     #[structopt(name = "values", help = "Values to be transmitted")]
//     values: Vec<String>,
// }

// fn main() {
//     let args = Arc::new(Mutex::new(Opt::from_args()));
//     let server = TcpListener::bind(&args.lock().unwrap().address).unwrap();
//     for stream in server.incoming() {
//         let args = args.clone();
//         let callback = |req: &Request| {
//             println!("Received a new ws handshake");
//             println!("The request's path is: {}", req.path);
//             println!("The request's headers are:");
//             for &(ref header, _ /* value */) in req.headers.iter() {
//                 println!("* {}", header);
//             }

//             // TODO: for better example decide based on the subprotocol if you send or receive
//             let extra_headers = vec![(String::from("Sec-WebSocket-Protocol"), String::from("ot"))];
//             Ok(Some(extra_headers))
//         };
//         spawn(move || {
//             let mut stream = accept_hdr(stream.unwrap(), callback).unwrap();
//             loop {
//                 if let Ok(Message::Binary(message)) = stream.read_message() {
//                     let rng = ChaChaRng::from_entropy();
//                     if message == "receive".as_bytes() {
//                         println!("Receiving values...");
//                         let now = Instant::now();
//                         let mut receiver = ChouOrlandiOTReceiver::new(
//                             stream,
//                             SHA3_256::default(),
//                             AesCryptoProvider::default(),
//                             rng,
//                         ).unwrap();
//                         let lock = args.lock().unwrap();
//                         let result = receiver.receive(lock.index, lock.length).unwrap();
//                         println!(
//                             "Got values: {} in {:?}",
//                             String::from_utf8(result).unwrap(),
//                             now.elapsed()
//                         );
//                         // TODO: make this more idiomatic
//                         stream = receiver.conn;
//                     } else if message == "send".as_bytes() {
//                         println!("Sending values...");
//                         let now = Instant::now();
//                         let mut sender = ChouOrlandiOTSender::new(
//                             stream,
//                             SHA3_256::default(),
//                             AesCryptoProvider::default(),
//                             rng,
//                         ).unwrap();
//                         let vals = args.lock().unwrap().values.to_owned();
//                         sender
//                             .send(
//                                 vals.iter()
//                                     .map(|s| {
//                                         let bytes = s.as_bytes();
//                                         bytes
//                                     })
//                                     .collect(),
//                             )
//                             .unwrap();
//                         println!("sent values in {:?}!", now.elapsed());
//                         stream = sender.conn;
//                     } else {
//                         println!("Could not understand message");
//                     }
//                 } else {
//                     println!("Socket closed!");
//                     break;
//                 }
//             }

//             //println!("{:?}", sender.compute_keys(10));
//         });
//     }
// }
