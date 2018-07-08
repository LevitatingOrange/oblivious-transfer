extern crate futures_core;
extern crate futures_util;
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
use futures_core::{Future, IntoFuture};
use futures_util::future::*;
use ot::async::base_ot::chou::{ChouOrlandiOTReceiver, ChouOrlandiOTSender};
//use ot::async::base_ot::{BaseOTReceiver, BaseOTSender};
use beaver_triples_gen::*;
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
use stdweb::traits::*;
use stdweb::unstable::TryInto;
use stdweb::web::event::ClickEvent;
use stdweb::web::html_element::InputElement;
use stdweb::web::Date;
use stdweb::web::TypedArray;
use stdweb::web::WebSocket;
use stdweb::web::{document, HtmlElement};
use stdweb::PromiseFuture;

fn output(s: &str) {
    let out = document().query_selector("#triple-out").unwrap().unwrap();
    let p: HtmlElement = document()
        .create_element("pre")
        .unwrap()
        .try_into()
        .unwrap();
    p.set_text_content(s);
    out.append_child(&p);
}

fn print(s: &str) {
    let console = document().query_selector("#console").unwrap().unwrap();
    let p: HtmlElement = document().create_element("p").unwrap().try_into().unwrap();
    p.set_text_content(s);
    console.append_child(&p);
}

fn error(s: &str) {
    let console = document().query_selector("#console").unwrap().unwrap();
    let p: HtmlElement = document().create_element("p").unwrap().try_into().unwrap();
    p.set_text_content(s);
    p.class_list().add("error").unwrap();
    console.append_child(&p);
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
    print("Creating BaseOT sender...");
    let prev = Date::now();
    ChouOrlandiOTSender::new(conn, SHA3_256::default(), AesCryptoProvider::default(), rng)
        .and_then(move |base_ot| {
            print(&format!(
                "BaseOT sender creation took {}ms",
                Date::now() - prev
            ));
            let rng = create_rng();
            print("Creating ExtendedOT receiver...");
            let prev = Date::now();
            IKNPExtendedOTReceiver::new(SHA3_256::default(), base_ot, rng, SECURITY_PARAM)
                .map(move |e| (prev, e))
        })
        .and_then(enclose! { (choices) move |(prev, ext_ot)| {
            print(&format!("ExtendedOT receiver creation took {}ms", Date::now() - prev));
            print("Receiving values...");
            let prev = Date::now();
            ext_ot.receive(choices).map(move |(qs, ext)| (prev, qs, ext))
        }})
        .map(|(prev, qs, ext_ot)| {
            print(&format!("ExtendedOT receive took {}ms", Date::now() - prev));
            let mut result = GFElement(0);
            for q in qs.into_iter().map(|e| GFElement::from_bytes(e)) {
                result += q;
            }
            (result, ext_ot.get_conn())
        })
        .and_then(|(result, conn)| {
            let rng = create_rng();
            print("Creating BaseOT receiver...");
            let prev = Date::now();
            ChouOrlandiOTReceiver::new(conn, SHA3_256::default(), AesCryptoProvider::default(), rng)
                .map(move |e| (prev, result, e))
        })
        .and_then(|(prev, result, base_ot)| {
            print(&format!(
                "BaseOT receiver creation took {}ms",
                Date::now() - prev
            ));
            let rng = create_rng();
            print("Creating ExtendedOT sender...");
            let prev = Date::now();
            IKNPExtendedOTSender::new(SHA3_256::default(), base_ot, rng, SECURITY_PARAM)
                .map(move |e| (prev, result, e))
        })
        .and_then(|(prev, result, ext_ot)| {
            print(&format!(
                "ExtendedOT sender creation took {}ms",
                Date::now() - prev
            ));
            print("sending values...");
            let prev = Date::now();
            ext_ot.send(pairs).map(move |e| (prev, result, e))
        })
        .map(move |(prev, recv_result, _)| {
            print(&format!("ExtendedOT send took {}ms", Date::now() - prev));
            let mut send_result = GFElement(0);
            for t in ts.into_iter() {
                send_result += t;
            }
            a * b + (-send_result) + recv_result
        })
}

fn start_computation(address: &str) {
    let mut rng = create_rng();
    let a = GFElement::random(&mut rng);
    let b = GFElement::random(&mut rng);
    let whole = Date::now();
    let future = WebSocket::new_with_protocols(address, &["ot"])
        .into_future()
        .map_err(|e| Error::with_chain(e, "Could not establish connection"))
        .and_then(|socket| WasmWebSocket::open(socket))
        .and_then(move |ws| calculate_beaver_triple(ws.clone(), a, b).map(|c| (c, ws)))
        .and_then(move |(c, conn)| {
            print("values sent.");
            print("Getting share from server for verification...");
            let lock = conn.lock().unwrap();
            lock.receive().map(move |(_, shares)| (c, shares))
        })
        .map(move |(c, shares)| {
            let other_a = GFElement::from_bytes(shares[..8].to_vec());
            let other_b = GFElement::from_bytes(shares[8..16].to_vec());
            let other_c = GFElement::from_bytes(shares[16..24].to_vec());
            output(&format!(
                "My triples:    [{:>20}] * [{:>20}] = [{:>20}]",
                a.0, b.0, c.0
            ));
            output(&format!(
                "Their triples: [{:>20}] * [{:>20}] = [{:>20}]",
                other_a.0, other_b.0, other_c.0
            ));
            output(&format!(
                "Combined:       {:>20}  *  {:>20}  {}  {:>20}",
                (other_a + a).0,
                (other_b + b).0,
                if (a + other_a) * (b + other_b) == (c + other_c) {
                    "="
                } else {
                    "≠"
                },
                (other_c + c).0
            ));
            print(&format!("Whole protocol (incl. WebSocket creation, verification and waiting for entropy for various rngs) took {}ms", Date::now() - whole))
        })
        .recover(|e| {
            error(&format!("{}", e.display_chain()));
            if let Some(ref backtrace) = e.backtrace() {
                error(&format!("Backtrace: {:?}", backtrace));
            }
        });
    PromiseFuture::spawn_local(future);
}

fn main() {
    stdweb::initialize();
    let btn = document().query_selector("#gen-btn").unwrap().unwrap();
    btn.add_event_listener(|_: ClickEvent| {
        let address_in: InputElement = document()
            .query_selector("#address-input")
            .unwrap()
            .unwrap()
            .try_into()
            .unwrap();
        start_computation(&address_in.raw_value());
    });
    stdweb::event_loop();
}
