extern crate futures;
#[macro_use]
extern crate stdweb;
extern crate error_chain;
extern crate ot;
extern crate pcg_rand;
extern crate rand;
extern crate sha3;

use error_chain::ChainedError;
use futures::prelude::*;
use ot::base_ot::async::chou::ChouOrlandiOTReceiver;
use ot::communication::async::websockets::*;
use ot::crypto::dummy::DummyCryptoProvider;
use ot::errors::*;
use pcg_rand::Pcg32;
use sha3::Sha3_256;
use std::sync::{Arc, Mutex};
use stdweb::traits::*;
use stdweb::unstable::TryInto;
use stdweb::web::EventListenerHandle;
use stdweb::web::WebSocket;
use stdweb::PromiseFuture;

use stdweb::web::event::{BlurEvent, ChangeEvent, ClickEvent, DoubleClickEvent, HashChangeEvent,
                         KeyPressEvent};
use stdweb::web::html_element::InputElement;
use stdweb::web::{document, window, Element, HtmlElement};

fn select(sel: &str) -> Element {
    document().query_selector(sel).unwrap().unwrap()
}

fn print_received_value(val: String) {
    let parent: HtmlElement = select(".ot-received-values").try_into().unwrap();
    let li: HtmlElement = document().create_element("li").unwrap().try_into().unwrap();
    li.class_list().add("ot-received-value").unwrap();
    li.set_text_content(&val);
    parent.append_child(&li);
}

fn error(val: &Error) {
    let err_div: HtmlElement = select(".receive-error").try_into().unwrap();
    err_div.class_list().add("error-visible").unwrap();
    err_div.set_text_content(val.description());
}

fn receive(ws: Arc<Mutex<WasmWebSocket>>, c: usize, n: usize) {
    // TODO: is this rng secure? Read the crate doc and about pcgs
    // TODO: use actual crypto provider, use javascript api
    // TODO: should we create it everytime
    console!(log, "Trying to receive value...");
    let rng = Pcg32::new_unseeded();
    let future =
        ChouOrlandiOTReceiver::new(ws, Sha3_256::default(), DummyCryptoProvider::default(), rng)
            .and_then(move |s| s.receive(c, n))
            .and_then(|result| {
                String::from_utf8(result)
                    .map_err(|e| Error::with_chain(e, "Error while parsing String"))
            })
            .map(print_received_value)
            .map_err(|e| {
                error(&e);
                PromiseFuture::print_error_panic(format!("{}", e.display_chain()))
            });
    PromiseFuture::spawn_local(future);
}

fn main() {
    stdweb::initialize();

    let connect_button = select(".connect-btn");

    let button_event_handle: Arc<Mutex<Option<EventListenerHandle>>> = Arc::new(Mutex::new(None));
    connect_button.add_event_listener(move |_: ClickEvent| {
        let btn_handle = button_event_handle.clone();
        let btn_handle2 = button_event_handle.clone();
        let mut lock = btn_handle.lock().unwrap();
        if let Some(handle) = (*lock).take() {
            console!(
                log,
                "Closing old connection (not correctly implemented yet)!"
            );
            handle.remove();
        }
        console!(log, "Establishing connection...");
        let address_elem: InputElement = select(".address").try_into().unwrap();
        let address = address_elem.raw_value();
        let future = WebSocket::new_with_protocols(&address, &["ot_receive"])
            .into_future()
            .map_err(|e| Error::with_chain(e, "Connection error"))
            .and_then(WasmWebSocket::open)
            .map(move |ws| {
                console!(log, "Connection established!");
                let receive_button = select(".ot-receive-btn");
                let mut lock = btn_handle2.lock().unwrap();
                *lock = Some(receive_button.add_event_listener(move |_: ClickEvent| {
                    let index_elem: InputElement = select(".ot-receive-index").try_into().unwrap();
                    let len_elem: InputElement = select(".ot-receive-len").try_into().unwrap();
                    let index: usize = index_elem
                        .raw_value()
                        .parse()
                        .map_err(|e| Error::with_chain(e, "couldn't parse index"))
                        .map_err(|e| error(&e))
                        .unwrap();
                    let len: usize = len_elem
                        .raw_value()
                        .parse()
                        .map_err(|e| Error::with_chain(e, "couldn't parse length"))
                        .map_err(|e| error(&e))
                        .unwrap();
                    receive(ws.clone(), index, len);
                }));
            })
            .map_err(|e| {
                error(&e);
                PromiseFuture::print_error_panic(format!("{}", e.display_chain()))
            });
        PromiseFuture::spawn_local(future);
    });

    stdweb::event_loop();
}

// fn main() {
//     stdweb::initialize();

//     let msg = "Hello World".to_owned();
//     let future = WasmWebSocket::open("ws://127.0.0.1:3012")
//         .unwrap()
//         .and_then(|ws| {
//             let lock = ws.lock().unwrap();
//             lock.write(msg.into_bytes())
//         })
//         .and_then(|ws| {
//             let lock = ws.lock().unwrap();
//             lock.read()
//         })
//         .map(|(_, result)| console!(log, String::from_utf8(result).unwrap()))
//         .map_err(|e| PromiseFuture::print_error_panic(e.description()));
//     PromiseFuture::spawn_local(future);
//     stdweb::event_loop();
// }
