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
use std::sync::{Arc, Mutex};
use stdweb::unstable::TryInto;
use stdweb::web::TypedArray;
use stdweb::web::WebSocket;
use stdweb::PromiseFuture;
use stdweb::web::Date;

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
    let mut rng = create_rng();
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
    let rng = create_rng();
    console!(log, "Creating BaseOT sender...");
    let prev = Date::now();
    ChouOrlandiOTSender::new(conn, SHA3_256::default(), AesCryptoProvider::default(), rng)
        .and_then(move |base_ot| {
            console!(log, "BaseOT sender creation took ", Date::now() - prev, "ms");
            let rng = create_rng();
            console!(log, "Creating ExtendedOT receiver...");
            let prev = Date::now();
            IKNPExtendedOTReceiver::new(SHA3_256::default(), base_ot, rng, SECURITY_PARAM).map(move |e| (prev, e))
        })
        .and_then(enclose! { (choices) move |(prev, ext_ot)| {
            console!(log, "ExtendedOT receiver creation took ", Date::now() - prev, "ms");
            console!(log, "Receiving values...");
            let prev = Date::now();
            ext_ot.receive(choices).map(move |(qs, ext)| (prev, qs, ext))
        }})
        .map(|(prev, qs, ext_ot)| {
            console!(log, "ExtendedOT receive took ", Date::now() - prev, "ms");
            let mut result = GFElement(0);
            for q in qs.into_iter().map(|e| GFElement::from_bytes(e)) {
                result += q;
            }
            (result, ext_ot.get_conn())
        })
        .and_then(|(result, conn)| {
            let rng = create_rng();
            console!(log, "Creating BaseOT receiver...");
            let prev = Date::now();
            ChouOrlandiOTReceiver::new(conn, SHA3_256::default(), AesCryptoProvider::default(), rng)
                .map(move |e| (prev, result, e))
        })
        .and_then(|(prev, result, base_ot)| {
            console!(log, "BaseOT receiver creation took ", Date::now() - prev, "ms");
            let rng = create_rng();
            console!(log, "Creating ExtendedOT sender...");
            let prev = Date::now();
            IKNPExtendedOTSender::new(SHA3_256::default(), base_ot, rng, SECURITY_PARAM)
                .map(move |e| (prev, result, e))
        })
        .and_then(|(prev, result, ext_ot)| {
            console!(log, "ExtendedOT sender creation took ", Date::now() - prev, "ms");
            console!(log, "sending values...");
            let prev = Date::now();
            ext_ot.send(pairs).map(move |e| (prev, result, e))
        })
        .map(move |(prev, recv_result, _)| {
            console!(log, "ExtendedOT send took ", Date::now() - prev, "ms");
            let mut send_result = GFElement(0);
            for t in ts.into_iter() {
                send_result += t;
            }
            a * b + (-send_result) + recv_result
        })
}
fn main() {
    stdweb::initialize();
    let mut rng = create_rng();
    let a = GFElement::random(&mut rng);
    let b = GFElement::random(&mut rng);
    console!(log, "Please disable privacy.reduceTimerPrecision and privacy.resistFingerprinting in Firefox or equivalent settings in chrome, so time measurements are precise!");
    let whole = Date::now();
    let future = WebSocket::new_with_protocols("ws://127.0.0.1:3012", &["ot"])
        .into_future()
        .map_err(|e| Error::with_chain(e, "Could not establish connection"))
        .and_then(|socket| WasmWebSocket::open(socket))
        .and_then(move |ws| calculate_beaver_triple(ws.clone(), a, b).map(|c| (c, ws)))
        .and_then(move |(c, conn)| {
            console!(log, "values sent.");
            console!(log, "Getting share from server for verification...");
            let lock = conn.lock().unwrap();
            lock.receive().map(move |(_, shares)| (c, shares))
        })
        .map(move |(c, shares)| {
            let other_a = GFElement::from_bytes(shares[..8].to_vec());
            let other_b = GFElement::from_bytes(shares[8..16].to_vec());
            let other_c = GFElement::from_bytes(shares[16..24].to_vec());
            console!(
                log,
                format!(
                    "My triples:    [{:>20}] * [{:>20}] = [{:>20}]",
                    a.0, b.0, c.0
                )
            );
            console!(
                log,
                format!(
                    "Their triples: [{:>20}] * [{:>20}] = [{:>20}]",
                    other_a.0, other_b.0, other_c.0
                )
            );
            console!(
                log,
                format!(
                    "Combined:       {:>20}  *  {:>20}  {}  {:>20}",
                    (other_a + a).0,
                    (other_b + b).0,
                    if (a + other_a) * (b + other_b) == (c + other_c) {"="} else {"≠"},
                    (other_c + c).0
                )
            );
            console!(log, "Whole protocol (incl. WebSocket creation, verification and waiting for entropy for various rngs) took ", Date::now() - whole, "ms")
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
