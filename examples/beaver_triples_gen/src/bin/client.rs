extern crate futures;
#[macro_use]
extern crate stdweb;
extern crate error_chain;
#[macro_use]
extern crate ot;
extern crate beaver_triples_gen;
extern crate bit_vec;
extern crate rand;
extern crate tiny_keccak;

use error_chain::ChainedError;
use futures::prelude::*;
use ot::async::base_ot::chou::{ChouOrlandiOTReceiver, ChouOrlandiOTSender};
//use ot::async::base_ot::{BaseOTReceiver, BaseOTSender};
use bit_vec::BitVec;
use ot::async::communication::websockets::*;
use ot::async::communication::{BinaryReceive, BinarySend, GetConn};
use ot::async::crypto::aes_browser::AesCryptoProvider;
use ot::async::ot_extension::iknp::{IKNPExtendedOTReceiver, IKNPExtendedOTSender};
use ot::async::ot_extension::{ExtendedOTReceiver, ExtendedOTSender};
use ot::common::digest::sha3::SHA3_256;
use ot::errors::*;
use rand::{ChaChaRng, SeedableRng};
use std::result;
use std::string;
use std::sync::{Arc, Mutex};
use stdweb::unstable::TryInto;
use stdweb::web::TypedArray;
use stdweb::web::WebSocket;
use stdweb::PromiseFuture;

use beaver_triples_gen::*;

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

fn calculate_beaver_triple<'a, T>(
    conn: Arc<Mutex<T>>,
    a: GFElement,
    b: GFElement,
) -> impl Future<Item = GFElement, Error = Error> + 'a
where
    T: 'a + BinarySend + BinaryReceive,
{
    let bytes = b.to_bytes();
    let choices: BitVec = BitVec::from_bytes(&bytes).into_iter().rev().collect();
    let s = format!("Length: {}", choices.len());
    console!(log, s);
    let rng = create_rng();
    console!(log, "Creating BaseOT sender...");
    ChouOrlandiOTSender::new(conn, SHA3_256::default(), AesCryptoProvider::default(), rng)
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
        .map(|(qs, _)| {
            let mut aggregated_result = GFElement(0);
            for q in qs.into_iter().map(|e| GFElement::from_bytes(e)) {
                aggregated_result += q;
            }
            aggregated_result
        })
}

fn main() {
    stdweb::initialize();
    let mut rng = create_rng();
    let a = GFElement::random(&mut rng);
    let b = GFElement::random(&mut rng);
    let future = WebSocket::new_with_protocols("ws://127.0.0.1:3012", &["ot"])
        .into_future()
        .map_err(|e| Error::with_chain(e, "Could not establish connection"))
        .and_then(|socket| WasmWebSocket::open(socket))
        .and_then(move |ws| calculate_beaver_triple(ws, a, b))
        .map(move |c| {
            let s = format!("a = [{}], b = [{}], c = [{}]", a.0, b.0, c.0);
            console!(log, s);
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
