#[macro_use]
extern crate criterion;
extern crate byte_tools;
extern crate ot;
extern crate rand;

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

fn tcp_setup(n: usize, l: usize, role: &str) -> (TcpStream, Vec<Vec<u8>>, usize, ChaChaRng) {
    let mut stream = TcpStream::connect("127.0.0.1:8123").unwrap();
    stream.send(role.as_bytes()).unwrap();

    let mut bytes: [u8; 8] = Default::default();

    write_u64_be(&mut bytes, n as u64);
    stream.send(&bytes).unwrap();
    write_u64_be(&mut bytes, l as u64);
    stream.send(&bytes).unwrap();

    let strings = create_random_strings(n, l);
    let vals = strings.into_iter().map(|s| s.into_bytes()).collect();
    let mut rng = ChaChaRng::from_entropy();
    let dist = Range::new(0, n);
    let choice = rng.sample(dist);
    (stream, vals, choice, rng)
}

fn ot_rust_tcp_send_setup_only(input: (TcpStream, Vec<Vec<u8>>, usize, ChaChaRng)) {
    //println!("Creating BaseOT receiver...");
    let mut ot = ChouOrlandiOTSender::new(
        input.0,
        SHA3_256::default(),
        AesCryptoProvider::default(),
        input.3,
    ).unwrap();
    //println!("chou ot receiver creation");
    //ot.send(input.1.iter().map(|s| s.as_slice()).collect()).unwrap();
}

fn ot_rust_tcp_send(input: (TcpStream, Vec<Vec<u8>>, usize, ChaChaRng)) {
    //println!("Creating BaseOT receiver...");
    let mut ot = ChouOrlandiOTSender::new(
        input.0,
        SHA3_256::default(),
        AesCryptoProvider::default(),
        input.3,
    ).unwrap();
    //println!("chou ot receiver creation");
    ot.send(input.1.iter().map(|s| s.as_slice()).collect())
        .unwrap();
}

fn ot_rust_tcp_receive_setup_only(input: (TcpStream, Vec<Vec<u8>>, usize, ChaChaRng)) {
    //println!("Creating BaseOT receiver...");
    let mut ot = ChouOrlandiOTReceiver::new(
        input.0,
        SHA3_256::default(),
        AesCryptoProvider::default(),
        input.3,
    ).unwrap();
    //println!("chou ot receiver creation");
    //ot.send(input.1.iter().map(|s| s.as_slice()).collect()).unwrap();
}

fn ot_rust_tcp_receive(input: (TcpStream, Vec<Vec<u8>>, usize, ChaChaRng)) {
    //println!("Creating BaseOT receiver...");
    let mut ot = ChouOrlandiOTReceiver::new(
        input.0,
        SHA3_256::default(),
        AesCryptoProvider::default(),
        input.3,
    ).unwrap();
    //println!("chou ot receiver creation");
    let values = ot.receive(input.2, input.1.len()).unwrap();
}

fn ot_native_send_benchmark(c: &mut Criterion) {
    let n = 100;
    let l = 64;
    c.bench_function(&format!("SimpleOT Sender TCP n={},l={}", n, l), move |b| {
        b.iter_with_setup(move || tcp_setup(n, l, "receive"), ot_rust_tcp_send)
    });
    c.bench_function(&format!("SimpleOT Sender TCP n={},l={} Setup Only", n, l), move |b| {
        b.iter_with_setup(
            move || tcp_setup(n, l, "receive"),
            ot_rust_tcp_send_setup_only,
        )
    });
    c.bench_function_over_inputs(&format!("ot_native_tcp_n_{}", l), move |b, &&growing_n| {
        b.iter_with_setup(move || tcp_setup(growing_n, l, "receive"), ot_rust_tcp_send)
    }, &[10, 100, 1000, 10000]);
    c.bench_function_over_inputs(
        &format!("SimpleOT Sender TCP n={}, l", n),
        move |b, &&growing_l| {
            b.iter_with_setup(move || tcp_setup(n, growing_l, "receive"), ot_rust_tcp_send)
        },
        &[32, 64, 128, 256],
    );
}

fn ot_native_receive_benchmark(c: &mut Criterion) {
    let n = 100;
    let l = 64;
    c.bench_function(
        &format!("SimpleOT Receiver TCP n={},l={}", n, l),
        move |b| b.iter_with_setup(move || tcp_setup(n, l, "send"), ot_rust_tcp_receive),
    );
    c.bench_function(
        &format!("SimpleOT Receiver TCP n={},l={}, Setup only", n, l),
        move |b| {
            b.iter_with_setup(
                move || tcp_setup(n, l, "send"),
                ot_rust_tcp_receive_setup_only,
            )
        },
    );
    c.bench_function_over_inputs(&format!("ot_native_tcp_n_{}", l), move |b, &&growing_n| {
        b.iter_with_setup(move || tcp_setup(growing_n, l, "receive"), ot_rust_tcp_receive)
    }, &[10, 100, 1000, 10000]);
    c.bench_function_over_inputs(
        &format!("SimpleOT Receiver TCP n={}, l", n),
        move |b, &&growing_l| {
            b.iter_with_setup(
                move || tcp_setup(n, growing_l, "send"),
                ot_rust_tcp_receive,
            )
        },
        &[32, 64, 128, 256],
    );
}

criterion_group!(
    benches,
    ot_native_send_benchmark,
    ot_native_receive_benchmark
);
criterion_main!(benches);
