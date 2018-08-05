extern crate futures_core;
extern crate futures_util;
#[macro_use]
extern crate stdweb;
extern crate error_chain;
#[macro_use]
extern crate ot;
extern crate rand;
extern crate tiny_keccak;

use error_chain::ChainedError;
use futures_core::Future;
use futures_core::IntoFuture;
use futures_util::future::*;
use ot::async::base_ot::chou::{ChouOrlandiOTReceiver, ChouOrlandiOTSender};
//use ot::async::base_ot::{BaseOTReceiver, BaseOTSender};
use ot::async::communication::websockets::*;
use ot::async::communication::GetConn;
use ot::async::crypto::aes_browser::AesCryptoProvider;
use ot::async::ot_extension::iknp::{IKNPExtendedOTReceiver, IKNPExtendedOTSender};
use ot::async::ot_extension::{ExtendedOTReceiver, ExtendedOTSender};
use ot::common::digest::sha3::SHA3_256;
use ot::common::util::{generate_random_choices, generate_random_string_pairs};
use ot::errors::*;
use rand::{ChaChaRng, SeedableRng};
use std::result;
use std::string;
use std::sync::{Arc, Mutex};
use stdweb::unstable::TryInto;
use stdweb::web::Date;
use stdweb::web::TypedArray;
use stdweb::web::WebSocket;
use stdweb::PromiseFuture;

const SECURITY_PARAM: usize = 16;
const VALUE_COUNT: usize = 1000;
const VALUE_LENGTH: usize = 64;
const EXTRA_COMPUTATIONS: usize = 99;

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

fn start_computation(num: usize, mut measurements: Vec<Arc<Mutex<[f64; 6]>>>) {
    let choices = generate_random_choices(VALUE_COUNT);
    let measurement: Arc<Mutex<[f64; 6]>> = Arc::new(Mutex::new(Default::default()));
    console!(log, "Opening WebSocket...");
    let future = WebSocket::new_with_protocols("ws://127.0.0.1:3012", &["ot"])
        .into_future()
        .map_err(|e| Error::with_chain(e, "Could not establish connection"))
        .and_then(|socket| WasmWebSocket::open(socket))
        .and_then(|ws| {
            console!(log, "WebSocket opened.");
            let rng = create_rng();
            console!(log, "Creating BaseOT sender...");
            let prev = now();
            ChouOrlandiOTSender::new(ws, SHA3_256::default(), AesCryptoProvider::default(), rng)
                .map(move |e| (prev, e))
        })
        .and_then(enclose! { (measurement) move |(prev, base_ot)| {
            let time = now() - prev;
            let mut lock = measurement.lock().unwrap();
            lock[0] = time;
            console!(log, "{}", &format!(
                "BaseOT sender creation took {}ms",
                time
            ));
            let rng = create_rng();
            console!(log, "Creating ExtendedOT receiver...");
            let prev = now();
            IKNPExtendedOTReceiver::new(SHA3_256::default(), base_ot, rng, SECURITY_PARAM).map(move |e| (prev, e))
        }})
        .and_then(enclose! { (measurement, choices) move |(prev, ext_ot)| {
            let time = now() - prev;
            let mut lock = measurement.lock().unwrap();
            lock[1] = time;
            console!(log, "{}", &format!(
                "ExtendedOT receiver creation took {}ms",
                time
            ));
            console!(log, "Receiving values...");
            let prev = now();
            ext_ot.receive(choices).map(move |(e, d)| (prev, e, d))
        }})
        .map(enclose! { (measurement) move |(prev, _, ext_ot)| {
            let time = now() - prev;
            let mut lock = measurement.lock().unwrap();
            lock[2] = time;
            console!(log, "{}", &format!(
                "ExtOT Receiver took {}ms",
                time
            ));
            ext_ot.get_conn()
        }})
        .and_then(move |conn| {
            let rng = create_rng();
            console!(log, "Creating BaseOT receiver...");
            let prev = now();
            ChouOrlandiOTReceiver::new(conn, SHA3_256::default(), AesCryptoProvider::default(), rng)
                .map(move |e| (prev, e))
        })
        .and_then(enclose! { (measurement) move |(prev, base_ot)| {
            let time = now() - prev;
            let mut lock = measurement.lock().unwrap();
            lock[3] = time;
            console!(log, "{}", &format!(
                "BaseOT Receiver creation took {}ms",
                time
            ));
            let rng = create_rng();
            console!(log, "Creating ExtendedOT sender...");
            let prev = now();
            IKNPExtendedOTSender::new(SHA3_256::default(), base_ot, rng, SECURITY_PARAM).map(move |e| (prev, e))
        }})
        .and_then(enclose! { (measurement) move |(prev, ext_ot)| {
            let time = now() - prev;
            let mut lock = measurement.lock().unwrap();
            lock[4] = time;
            console!(log, "{}", &format!(
                "ExtendedOT Receiver creation took {}ms",
                time
            ));
            let values = generate_random_string_pairs(VALUE_LENGTH, VALUE_COUNT);
            console!(log, "sending values...");
            let prev = now();
            ext_ot.send(values.into_iter()
                .map(|(s1, s2)| (s1.into_bytes(), s2.into_bytes()))
                .collect()).map(move |e| (prev, e))
        }})
        .map(enclose! { (measurement) move |(prev, _)| {
            let time = now() - prev;
            {
            let mut lock = measurement.lock().unwrap();
            lock[5] = time;
            }
            console!(log, "{}", &format!(
                "ExtendedOT Sender took {}ms",
                time
            ));
            measurements.push(measurement);
            if num > 0 {
                start_computation(num - 1, measurements);
            } else {
                for measurement in measurements.iter() {
                    let lock = measurement.lock().unwrap();
                    let mut string = String::new();
                    for val in lock.iter() {
                        string.push_str(&val.to_string());
                        string.push(',');
                    }
                    string.push_str(&(lock[0] + lock[1] + lock[2]).to_string());
                    string.push(',');
                    string.push_str(&(lock[3] + lock[4] + lock[5]).to_string());
                    string.push(',');
                    console!(log, string);
                }
            }
        }})
        .recover(|e| {
            //console!(error, format!("{}", e.display_chain()));
            if let Some(ref backtrace) = e.backtrace() {
                console!(error, format!("Backtrace: {:?}", backtrace));
            }
        });
    PromiseFuture::spawn_local(future);
}

fn main() {
    stdweb::initialize();

    start_computation(
        EXTRA_COMPUTATIONS,
        Vec::with_capacity(EXTRA_COMPUTATIONS + 1),
    );

    stdweb::event_loop();
}
