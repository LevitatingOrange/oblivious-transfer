#![feature(async_await, await_macro, futures_api)]

use failure::Fallible;

use std::io;
use romio::{TcpListener, TcpStream};
use futures::prelude::*;
use futures::executor::{self, ThreadPool};
use futures::task::{SpawnExt};


use ot::base_ot::simple_ot::{SimpleOTSender, SimpleOTReceiver};
use ot::crypto::sha3::SHA3_256;
use ot::native::aes::AesCryptoProvider;
use ot::util::generate_random_strings;
use std::env::args;

use rand::{Rng, ChaChaRng, FromEntropy};

async fn run(receive: bool) -> Fallible<()> {
    const N: usize = 20;
    const L: usize = 64;

    if receive {
        let crypto_provider = AesCryptoProvider::default();
        let hasher = SHA3_256::default();
        let mut rng = ChaChaRng::from_entropy();

        let random_index = rng.gen_range(0, N);

        let stream = await!(TcpStream::connect(&"127.0.0.1:8080".parse().unwrap()))?;
        let mut receiver = await!(SimpleOTReceiver::new(stream, hasher, crypto_provider, rng))?;
        let rec_val = await!(receiver.receive(random_index, N))?;
        println!("Received value \"{}\" with index {}", String::from_utf8(rec_val)?,random_index);
    } else {
        let mut threadpool = ThreadPool::new()?;

        let listener = TcpListener::bind(&"127.0.0.1:8080".parse().unwrap())?;
        let mut incoming = listener.incoming();

         while let Some(stream) = await!(incoming.next()) {
            let stream = stream?;

            threadpool.spawn(async move {
                let crypto_provider = AesCryptoProvider::default();
                let hasher = SHA3_256::default();
                let mut rng = ChaChaRng::from_entropy();

                let random_strings = generate_random_strings(&mut rng, N, L);
                println!("Sent values: {:?}", random_strings);
                let random_byte_vecs: Vec<&[u8]> = random_strings.iter().map(|s|s.as_bytes()).collect();

                let mut sender = await!(SimpleOTSender::new(stream, hasher, crypto_provider, rng)).unwrap();
                await!(sender.send(&random_byte_vecs)).unwrap();
            }).unwrap();
        }
    }
    Ok(())
}

fn main() -> Fallible<()> {

    let receive: bool = args().nth(1).unwrap().parse().unwrap();

    // And we are async...
    executor::block_on(async move {
        await!(run(receive))?;
        Ok(())
    })
}