#[macro_use]
extern crate criterion;
extern crate ot;
extern crate rand;
extern crate byte_tools;

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
use std::net::TcpStream;
use std::thread::spawn;
use std::time::Instant;

use byte_tools::write_u64_be;

use criterion::Criterion;

fn tcp_setup(n: usize, l: usize, role: &str) -> (TcpStream, Vec<Vec<u8>>, ChaChaRng) {
    let mut stream = TcpStream::connect("127.0.0.1:8123").unwrap();
    stream.send(role.as_bytes()).unwrap();

    let mut bytes: [u8; 8] = Default::default();

    write_u64_be(&mut bytes, n as u64);

    stream.send(&bytes).unwrap();
    let strings = create_random_strings(n, l);
    let vals = strings.into_iter().map(|s| s.into_bytes()).collect();
    let rng = ChaChaRng::from_entropy();
    (stream, vals, rng)
}

fn ot_rust_tcp_send(input: (TcpStream, Vec<Vec<u8>>, ChaChaRng)) {
    //println!("Creating BaseOT receiver...");
    let mut ot = ChouOrlandiOTSender::new(
        input.0,
        SHA3_256::default(),
        AesCryptoProvider::default(),
        input.2,
    ).unwrap();
    //println!("chou ot receiver creation");
    ot.send(input.1.iter().map(|s| s.as_slice()).collect()).unwrap();
}

fn ot_rust_tcp_benchmark(c: &mut Criterion) {
    let n = 100;
    let l = 20;
    c.bench_function("ot_100_20", move |b| {
        b.iter_with_setup(move || tcp_setup(n, l, "receive"), ot_rust_tcp_send)
    });
}

criterion_group!(benches, ot_rust_tcp_benchmark);
criterion_main!(benches);