extern crate beaver_triples_gen;
extern crate bit_vec;
extern crate ot;
extern crate rand;
extern crate tungstenite;

use bit_vec::BitVec;
use ot::common::digest::sha3::SHA3_256;
use ot::sync::base_ot::chou::{ChouOrlandiOTReceiver, ChouOrlandiOTSender};
use ot::sync::communication::{BinaryReceive, BinarySend, GetConn};
use ot::sync::crypto::aes::AesCryptoProvider;
use ot::sync::ot_extension::iknp::{IKNPExtendedOTReceiver, IKNPExtendedOTSender};
use ot::sync::ot_extension::{ExtendedOTReceiver, ExtendedOTSender};
use rand::{ChaChaRng, FromEntropy};
use std::net::TcpListener;
use std::thread::spawn;
use tungstenite::handshake::server::Request;
use tungstenite::server::accept_hdr;

use std::time::Instant;

use beaver_triples_gen::*;

fn calculate_beaver_triple<T>(conn: T, a: GFElement, b: GFElement) -> GFElement
where
    T: BinaryReceive + BinarySend,
{
    let mut rng = ChaChaRng::from_entropy();

    let ts: Vec<GFElement> = (0..K).map(|_| GFElement::random(&mut rng)).collect();
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = ts
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let x = a * GFElement::new(1 << i);
            (t.to_bytes(), (*t + x).to_bytes())
        })
        .collect();
    let bytes = b.to_bytes();
    let choices: BitVec = BitVec::from_bytes(&bytes).into_iter().rev().collect();

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

    let mut send_result = GFElement(0);
    for t in ts.into_iter() {
        send_result += t;
    }

    rng = ChaChaRng::from_entropy();

    println!("Creating BaseOT sender...");
    now = Instant::now();
    let ot_send = ChouOrlandiOTSender::new(
        ot_ext_send.get_conn(),
        SHA3_256::default(),
        AesCryptoProvider::default(),
        rng,
    ).unwrap();
    println!("chou ot sender creation took {:?}", now.elapsed());

    rng = ChaChaRng::from_entropy();
    now = Instant::now();
    let mut ot_ext_recv =
        IKNPExtendedOTReceiver::new(SHA3_256::default(), ot_send, rng.clone(), SECURITY_PARAM)
            .unwrap();
    println!("IKNP receiver creation took {:?}", now.elapsed());
    now = Instant::now();
    let qs = ot_ext_recv.receive(&choices).unwrap();
    println!("IKNP send took {:?}", now.elapsed());

    let mut recv_result = GFElement(0);
    for q in qs.into_iter().map(|e| GFElement::from_bytes(e)) {
        recv_result += q;
    }

    let c = a * b + (-send_result) + recv_result;
    println!("Sending to client for verification...");
    let mut v1 = a.to_bytes();
    let mut v2 = b.to_bytes();
    let mut v3 = c.to_bytes();
    v1.append(&mut v2);
    v1.append(&mut v3);
    ot_ext_recv.get_conn().send(&v1).unwrap();
    println!("Sent to client for verification.");
    c
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
            let now = Instant::now();
            let stream = accept_hdr(stream.unwrap(), callback).unwrap();
            let mut rng = ChaChaRng::from_entropy();

            let a = GFElement::random(&mut rng);
            let b = GFElement::random(&mut rng);
            let c = calculate_beaver_triple(stream, a, b);

            println!("Triple generated: [{}] * [{}] = [{}]", a.0, b.0, c.0);
            println!("Whole protocol (incl. WebSocket creation, verification and waiting for entropy for various rngs) took {:?}", now.elapsed())
        });
    }
}
