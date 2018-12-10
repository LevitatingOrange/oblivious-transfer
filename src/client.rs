#![feature(async_await, await_macro, futures_api)]
use failure::Fallible;

use std::io;
use futures::prelude::*;
use futures::executor::{self, ThreadPool};
use futures::task::{SpawnExt};


use ot::base_ot::simple_ot::{SimpleOTSender, SimpleOTReceiver};
use ot::crypto::sha3::SHA3_256;
use ot::browser::aes::AesCryptoProvider;
use ot::browser::websockets::*;
use ot::util::generate_random_strings;
use std::env::args;

use stdweb::*;
use stdweb::web::TypedArray;
use stdweb::unstable::TryInto;

use rand::{Rng, ChaChaRng, FromEntropy};
use rand::SeedableRng;

fn now() -> f64 {
    let mus: f64 = js!( return performance.now(); ).try_into().unwrap();
    mus / 1000_f64
}
fn create_rng() -> ChaChaRng {
    let seed: TypedArray<u8> = js!{
        var array = new Uint8Array(32);
        window.crypto.getRandomValues(array);
        return array;
    }.try_into()
        .unwrap();
    let mut seed_arr: [u8; 32] = Default::default();
    seed_arr.copy_from_slice(&seed.to_vec());
    ChaChaRng::from_seed(seed_arr)
}

async fn run(receive: bool) -> Fallible<()> {
    const N: usize = 20;
    const L: usize = 64;

    if receive {
        let crypto_provider = AesCryptoProvider::default();
        let hasher = SHA3_256::default();
        let mut rng = create_rng();

        let random_index = rng.gen_range(0, N);

        let stream = await!(WebSocket::new_with_protocols("ws://127.0.0.1:8080", &["ot"]).into_future());

        // let stream = await!(TcpStream::connect(&"127.0.0.1:8080".parse().unwrap()))?;
        // let mut receiver = await!(SimpleOTReceiver::new(stream, hasher, crypto_provider, rng))?;
        // let rec_val = await!(receiver.receive(random_index, N))?;
        // println!("Received value \"{}\" with index {}", String::from_utf8(rec_val)?,random_index);
    } 
    // else {
    //     let mut threadpool = ThreadPool::new()?;

    //     let listener = TcpListener::bind(&"127.0.0.1:8080".parse().unwrap())?;
    //     let mut incoming = listener.incoming();
    //     let crypto_provider = AesCryptoProvider::default();
    //     let hasher = SHA3_256::default();
    //     let mut rng = ChaChaRng::from_entropy();

    //     let random_strings = generate_random_strings(N, L);
    //     println!("Sent values: {:?}", random_strings);
    //     let random_byte_vecs: Vec<&[u8]> = random_strings.iter().map(|s|s.as_bytes()).collect();

    //     let mut sender = await!(SimpleOTSender::new(stream, hasher, crypto_provider, rng)).unwrap();
    //     await!(sender.send(&random_byte_vecs)).unwrap();  
    // }
    Ok(())
}

fn main() {

}