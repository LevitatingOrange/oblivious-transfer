extern crate beaver_triples_gen;
extern crate ot;
extern crate rand;
extern crate tungstenite;

use ot::common::digest::sha3::SHA3_256;
use ot::common::util::{generate_random_choices, generate_random_string_pairs};
use ot::sync::base_ot::chou::{ChouOrlandiOTReceiver, ChouOrlandiOTSender};
use ot::sync::communication::{BinaryReceive, BinarySend, GetConn};
use ot::sync::crypto::aes::AesCryptoProvider;
use ot::sync::ot_extension::iknp::{IKNPExtendedOTReceiver, IKNPExtendedOTSender};
use ot::sync::ot_extension::{ExtendedOTReceiver, ExtendedOTSender};
use rand::distributions::range::Range;
use rand::{ChaChaRng, CryptoRng, FromEntropy, RngCore};
use std::net::TcpListener;
use std::thread::spawn;
use tungstenite::handshake::server::Request;
use tungstenite::server::accept_hdr;

use rand::distributions::Distribution;
use std::ops::{Add, AddAssign, Mul, Neg, Sub};
use std::time::Instant;

use beaver_triples_gen::*;

fn calculate_beaver_triple<T>(conn: T, a: GFElement, b: GFElement) -> GFElement
where
    T: BinaryReceive + BinarySend,
{
    let range = Range::new(0, MODULUS);
    let mut rng = ChaChaRng::from_entropy();

    let ts: Vec<GFElement> = (0..K).map(|_| GFElement::random(&mut rng)).collect();
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = ts
        .iter()
        .map(|t| (t.to_bytes(), (*t + a).to_bytes()))
        .collect();

    let mut rng = ChaChaRng::from_entropy();
    println!("Creating BaseOT receiver...");
    let mut now = Instant::now();
    let ot_recv =
        ChouOrlandiOTReceiver::new(conn, SHA3_256::default(), AesCryptoProvider::default(), rng)
            .unwrap();
    println!("chou ot receiver creation took {:?}", now.elapsed());
    rng = ChaChaRng::from_entropy();
    println!("Creating OTExtension sender...");
    now = Instant::now();
    let mut ot_ext_send =
        IKNPExtendedOTSender::new(SHA3_256::default(), ot_recv, rng, SECURITY_PARAM).unwrap();
    println!("IKNP sender creation took {:?}", now.elapsed());
    println!("Sending values...");
    now = Instant::now();

    ot_ext_send
        .send(pairs.iter().map(|(p1, p2)| (&p1[..], &p2[..])).collect())
        .unwrap();
    println!("IKNP send took {:?}", now.elapsed());

    let mut aggregated_result = GFElement(0);
    for (i, t) in ts.iter().enumerate() {
        aggregated_result += *t * GFElement((1 as u64) << (i as u64));
    }
    -aggregated_result

    //rng = ChaChaRng::from_entropy();

    // println!("Creating BaseOT sender...");
    // now = Instant::now();
    // let ot_send = ChouOrlandiOTSender::new(
    //     ot_ext_send.get_conn(),
    //     SHA3_256::default(),
    //     AesCryptoProvider::default(),
    //     rng,
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
    // let zipped: Vec<(bool, String)> = choice_bits
    //     .iter()
    //     .zip(values.into_iter().map(|s| String::from_utf8(s).unwrap()))
    //     .collect();
    // println!("Received values: {:?}", zipped);
}

fn main() {
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
            let stream = accept_hdr(stream.unwrap(), callback).unwrap();
            let range = Range::new(0, MODULUS);
            let mut rng = ChaChaRng::from_entropy();

            let a = GFElement::random(&mut rng);
            let b = GFElement::random(&mut rng);
            let c = calculate_beaver_triple(stream, a, b);

            println!("[{}] * [{}] = [{}]", a.0, b.0, c.0);

            //println!("{:?}", sender.compute_keys(10));
        });
    }
}
