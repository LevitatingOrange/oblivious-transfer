extern crate byte_tools;
/// used to allow benchmarking
extern crate ot;
extern crate rand;

extern crate tungstenite;

use ot::common::digest::sha3::SHA3_256;
use ot::common::util::{
    create_random_strings, generate_random_choices, generate_random_string_pairs,
};
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
use tungstenite::server::accept;

use std::env::args;

fn serve<T>(mut stream: T, n: usize, l: usize, comm_switch: bool)
where
    T: BinarySend + BinaryReceive,
{
    let mut rng = ChaChaRng::from_entropy();



    if comm_switch {
        //println!("Bytes: {:?}", bytes);
        //println!("Length: {}", n);
        let dist = Range::new(0, n);
        let choice = rng.sample(dist);
        //println!("Generated random index: {:?}", choice);
        //println!("Creating BaseOT receiver...");
        //let mut now = Instant::now();
        //stream.send("sync".as_bytes()).unwrap();
        let mut ot_recv = ChouOrlandiOTReceiver::new(
            stream,
            SHA3_256::default(),
            AesCryptoProvider::default(),
            rng.clone(),
        ).unwrap();
        //println!("chou ot receiver creation took {:?}", now.elapsed());
        //now = Instant::now();
        let values = ot_recv.receive(choice, n).unwrap();
    //println!("Received values: {:?}", values);
    //println!("OT receive took {:?}", now.elapsed());
    } else {
        let strings: Vec<Vec<u8>> = create_random_strings(n, l)
            .into_iter()
            .map(|s| s.into_bytes())
            .collect();
        //stream.send("sync".as_bytes()).unwrap();
        let mut ot = ChouOrlandiOTSender::new(
            stream,
            SHA3_256::default(),
            AesCryptoProvider::default(),
            rng,
        ).unwrap();
        ot.send(strings.iter().map(|s| s.as_slice()).collect())
            .unwrap();
    }
}

fn serve_ote<T>(mut stream: T, n: usize, l: usize, comm_switch: bool)
where
    T: BinarySend + BinaryReceive,
{
    let mut rng = ChaChaRng::from_entropy();

    if comm_switch {
        let choices = generate_random_choices(n);
        let mut ot = ChouOrlandiOTSender::new(
            stream,
            SHA3_256::default(),
            AesCryptoProvider::default(),
            rng.clone(),
        ).unwrap();

        let mut ote = IKNPExtendedOTReceiver::new(SHA3_256::default(), ot, rng.clone(), 16).unwrap();
        ote.receive(&choices).unwrap();
    } else {
        let strings: Vec<(Vec<u8>, Vec<u8>)> = generate_random_string_pairs(l, n)
            .into_iter()
            .map(|(s1, s2)| (s1.into_bytes(), s2.into_bytes()))
            .collect();

        let mut ot = ChouOrlandiOTReceiver::new(
            stream,
            SHA3_256::default(),
            AesCryptoProvider::default(),
            rng.clone(),
        ).unwrap();

        let mut ote = IKNPExtendedOTSender::new(SHA3_256::default(), ot, rng.clone(), 16).unwrap();
        ote.send(
            strings
                .iter()
                .map(|(s1, s2)| (s1.as_slice(), s1.as_slice()))
                .collect(),
        ).unwrap();
    }
}

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
            let mut stream = stream.unwrap();
            let stream_switch =
                &String::from_utf8(stream.receive().unwrap()).unwrap() == "websocket";
            let comm_switch = &String::from_utf8(stream.receive().unwrap()).unwrap() == "receive";
            let iknp_switch = &String::from_utf8(stream.receive().unwrap()).unwrap() == "iknp";

            let bytes = stream.receive().unwrap();
            let n = read_u64_be(&bytes) as usize;
            let bytes = stream.receive().unwrap();
            let l = read_u64_be(&bytes) as usize;

            if iknp_switch {
                if stream_switch {
                    // Websocket
                    serve_ote(accept(stream).unwrap(), n, l, comm_switch);
                } else {
                    // Tcp
                    serve_ote(stream, n, l, comm_switch);
                }
            } else {
                if stream_switch {
                    // Websocket
                    serve(accept(stream).unwrap(), n, l, comm_switch);
                } else {
                    // Tcp
                    serve(stream, n, l, comm_switch);
                }
            }
        });
    }
}
