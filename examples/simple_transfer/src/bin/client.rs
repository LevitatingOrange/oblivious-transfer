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
use futures_core::IntoFuture;
use futures_util::future::*;
use ot::async::base_ot::chou::{ChouOrlandiOTReceiver, ChouOrlandiOTSender};
//use ot::async::base_ot::{BaseOTReceiver, BaseOTSender};
use ot::async::communication::websockets::*;
use ot::async::communication::{GetConn};
use ot::async::crypto::aes_browser::AesCryptoProvider;
use ot::async::ot_extension::iknp::{IKNPExtendedOTReceiver, IKNPExtendedOTSender};
use ot::async::ot_extension::{ExtendedOTReceiver, ExtendedOTSender};
use ot::common::digest::sha3::SHA3_256;
use ot::common::util::{generate_random_choices, generate_random_string_pairs};
use ot::errors::*;
use rand::{ChaChaRng, SeedableRng};
use stdweb::unstable::TryInto;
use stdweb::web::TypedArray;
use stdweb::web::WebSocket;
use std::result;
use std::string;
use stdweb::PromiseFuture;

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

fn main() {
    stdweb::initialize();

    const SECURITY_PARAM: usize = 16;
    const VALUE_COUNT: usize = 10;
    const VALUE_LENGTH: usize = 5;

    let choices = generate_random_choices(VALUE_COUNT);

    console!(log, "Opening WebSocket...");
    let future = WebSocket::new_with_protocols("ws://127.0.0.1:3012", &["ot"])
        .into_future()
        .map_err(|e| Error::with_chain(e, "Could not establish connection"))
        .and_then(|socket| WasmWebSocket::open(socket))
        .and_then(|ws| {
            console!(log, "WebSocket opened.");
            let rng = create_rng();
            console!(log, "Creating BaseOT sender...");
            ChouOrlandiOTSender::new(ws, SHA3_256::default(), AesCryptoProvider::default(), rng)
        })
        .and_then(|base_ot| {
            console!(log, "BaseOT sender created.");
            let rng = create_rng();
            console!(log, "Creating ExtendedOT receiver...");
            IKNPExtendedOTReceiver::new(SHA3_256::default(), base_ot, rng, SECURITY_PARAM)
        })
        .and_then(enclose! { (choices) move |ext_ot| {
            console!(log, "ExtendedOT receiver created.");
            console!(log, "Receiving values...");
            ext_ot.receive(choices)
        }})
        .and_then(|(vals, ext_ot)| {
            let strings: result::Result<Vec<String>, string::FromUtf8Error> =
                vals.into_iter().map(|s| String::from_utf8(s)).collect();
            strings
                .map(|strings| (strings, ext_ot.get_conn()))
                .map_err(|e| Error::with_chain(e, "Error while parsing String"))
        })
        .and_then(enclose! { (choices) move |(vals, conn)| {
            let zipped: Vec<(bool, String)> = choices.iter().zip(vals).collect();
            let s = format!("Received values: {:?}", zipped);
            console!(log, s);
            let rng = create_rng();
            console!(log, "Creating BaseOT receiver...");
            ChouOrlandiOTReceiver::new(conn, SHA3_256::default(), AesCryptoProvider::default(), rng)
        }})
        .and_then(|base_ot| {
            console!(log, "BaseOT receiver created.");
            let rng = create_rng();
            console!(log, "Creating ExtendedOT sender...");
            IKNPExtendedOTSender::new(SHA3_256::default(), base_ot, rng, SECURITY_PARAM)
        })
        .and_then(move |ext_ot| {
            console!(log, "ExtendedOT sender created.");
            let values = generate_random_string_pairs(VALUE_LENGTH, VALUE_COUNT);
            let s = format!("Values: {:?}", values);
            console!(log, s);
            console!(log, "sending values...");
            ext_ot.send(values.into_iter()
                .map(|(s1, s2)| (s1.into_bytes(), s2.into_bytes()))
                .collect())
        })
        .map(move |_| {
            console!(log, "values sent.");
        })
        .recover(|e| {
            console!(error, format!("{}", e.display_chain()));
            if let Some(ref backtrace) = e.backtrace() {
                console!(error, format!("Backtrace: {:?}", backtrace));
            }
        });
    PromiseFuture::spawn_local(future);
    stdweb::event_loop();
}
