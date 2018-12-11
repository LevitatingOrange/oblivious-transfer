#![feature(async_await, await_macro, futures_api)]
use failure::Fallible;

use futures::prelude::*;
use futures::executor::{self, ThreadPool};
use futures::task::{SpawnExt};


//use ot::base_ot::simple_ot::{SimpleOTSender, SimpleOTReceiver};
use ot::extended_ot::iknp::*;
use ot::crypto::sha3::SHA3_256;
use ot::browser::aes::AesCryptoProvider;
use ot::browser::websockets::*;
use ot::util::{generate_random_choices, generate_random_string_pairs};
use std::env::args;

use stdweb::*;
use stdweb::web::TypedArray;
use stdweb::unstable::TryInto;
use stdweb::web::WebSocket;
use stdweb::PromiseFuture;

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

async fn run(value_count: usize) -> Fallible<()> {
    const SECURITY_PARAM: usize = 16;
    const VALUE_LENGTH: usize = 64;
    const NUM_EXPERIMENTS: usize = 100;

    let mut send_results = Vec::with_capacity(NUM_EXPERIMENTS);
    let mut receive_results = Vec::with_capacity(NUM_EXPERIMENTS);

    for i in 0..NUM_EXPERIMENTS {

        let stream = await!(WasmWebSocket::open(WebSocket::new_with_protocols("ws://127.0.0.1:3012", &["ot"])?));

        let mut rng = ChaChaRng::from_seed([0u8; 32]);

        let values = generate_random_string_pairs(&mut rng, VALUE_LENGTH, value_count);
        let choice_bits = generate_random_choices(&mut rng, value_count);
        //println!("Generated values: {:?}", values);
        //sleep(Duration::from_millis(500));

        let mut before = now();
        
        let mut ot_ext_recv: IKNPExtendedOTReceiver<WasmWebSocketAsync, SHA3_256> = await!(IKNPExtendedOTReceiver::new(
            stream,
            SHA3_256::default(),
            AesCryptoProvider::default(),
            rng.clone(),
            SECURITY_PARAM,
        ))?;
        let result = await!(ot_ext_recv.receive(choice_bits))?;

        receive_results.push(now() - before);

        let values: Vec<(Vec<u8>, Vec<u8>)> = values
            .into_iter()
            .map(|(s1, s2)| (s1.into_bytes(), s2.into_bytes()))
            .collect();

        let mut rng = ChaChaRng::from_seed([0u8; 32]);

        before = now();
        let mut ot_ext_send = await!(IKNPExtendedOTSender::new(
            ot_ext_recv.conn,
            SHA3_256::default(),
            AesCryptoProvider::default(),
            rng.clone(),
            SECURITY_PARAM,
        ))?;

        await!(ot_ext_send.send(values))?;

        send_results.push(now() - before);
    }
    Ok(())
}

fn main() {
    stdweb::initialize();
    
    // Failure's Error does not implement JsSerialize so we convert it to a string here.
    // Failure will eventually be replaced with a custom error type for this crate.
    spawn_local(unwrap_future(run(10).map_err(|e| e.to_string())));

    stdweb::event_loop();
}