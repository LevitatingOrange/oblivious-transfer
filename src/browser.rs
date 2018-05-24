extern crate futures;
#[macro_use]
extern crate stdweb;
extern crate error_chain;
extern crate ot;
extern crate pcg_rand;
extern crate rand;
extern crate tiny_keccak;

use error_chain::ChainedError;
use futures::prelude::*;
use ot::async::base_ot::chou::{ChouOrlandiOTReceiver, ChouOrlandiOTSender};
use ot::async::communication::websockets::*;
use ot::async::crypto::aes_browser::AesCryptoProvider;
use ot::errors::*;
use ot::common::digest::sha3::SHA3_256;
use rand::{ChaChaRng, SeedableRng};
use std::sync::{Arc, Mutex};
use stdweb::traits::*;
use stdweb::unstable::TryInto;
use stdweb::web::EventListenerHandle;
use stdweb::web::WebSocket;
use stdweb::PromiseFuture;
use stdweb::web::event::{ClickEvent, SocketCloseEvent};
use stdweb::web::html_element::InputElement;
use stdweb::web::TypedArray;
use stdweb::web::{document, Element, HtmlElement};

fn select(sel: &str) -> Element {
    document().query_selector(sel).unwrap().unwrap()
}

fn print_received_value(val: String) {
    let parent: HtmlElement = select(".ot-receive").try_into().unwrap();
    let elem: HtmlElement = document()
        .create_element("div")
        .unwrap()
        .try_into()
        .unwrap();
    elem.class_list().add("row").unwrap();
    elem.set_text_content(&val);
    parent.append_child(&elem);
}

fn error(val: &Error) {
    let err_div: HtmlElement = select(".error").try_into().unwrap();
    err_div.class_list().add("error-visible").unwrap();
    err_div.set_text_content(val.description());
}

fn receive(ws: Arc<Mutex<WasmWebSocket>>, c: usize, n: usize) {
    // TODO: is this rng secure? Read the crate doc and about pcgs
    // TODO: make example with single Receiver that it used more than once, fix it first
    let handle = ws.clone();
    let lock = handle.lock().unwrap();
    console!(log, "Trying to receive value...");
    let seed: TypedArray<u32> = js!{
        var array = new Uint32Array(8);
        window.crypto.getRandomValues(array);
        return array;
    }.try_into()
        .unwrap();
    let rng = ChaChaRng::from_seed(&seed.to_vec());
    let future = lock.write("send".as_bytes().to_owned())
        .and_then(move |_| {
            ChouOrlandiOTReceiver::new(ws, SHA3_256::default(), AesCryptoProvider::default(), rng)
        })
        .and_then(move |s| s.receive(c, n))
        .and_then(|(_, result)| {
            String::from_utf8(result)
                .map_err(|e| Error::with_chain(e, "Error while parsing String"))
        })
        .map(move |result| {
            console!(log, "Value received!");
            print_received_value(result)
        })
        .recover(|e| {
            console!(error, format!("{}", e.display_chain()));
            if let Some(ref backtrace) = e.backtrace() {
                console!(error, format!("Backtrace: {:?}", backtrace));
            }
            error(&e);
        });
    PromiseFuture::spawn_local(future);
}

fn send(ws: Arc<Mutex<WasmWebSocket>>, values: Vec<Vec<u8>>) {
    let handle = ws.clone();
    let lock = handle.lock().unwrap();
    // TODO: is this rng secure? Read the crate doc and about pcgs
    console!(log, "Trying to send values...");
    let seed: TypedArray<u32> = js!{
        var array = new Uint32Array(8);
        window.crypto.getRandomValues(array);
        return array;
    }.try_into()
        .unwrap();
    let mut rng = ChaChaRng::from_seed(&seed.to_vec());
    let future = lock.write("receive".as_bytes().to_owned())
        .and_then(move |_| {
            ChouOrlandiOTSender::new(
                ws,
                SHA3_256::default(),
                AesCryptoProvider::default(),
                &mut rng,
            )
        })
        .and_then(move |s| s.send(values))
        .map(|_| console!(log, "values sent!"))
        .recover(|e| {
            console!(error, format!("{}", e.display_chain()));
            if let Some(ref backtrace) = e.backtrace() {
                console!(error, format!("Backtrace: {:?}", backtrace));
            }
            error(&e);
        });
    PromiseFuture::spawn_local(future);
}

fn main() {
    stdweb::initialize();

    let connect_button = select(".connect-btn");

    let button_receive_event_handle: Arc<Mutex<Option<EventListenerHandle>>> =
        Arc::new(Mutex::new(None));
    let button_send_event_handle: Arc<Mutex<Option<EventListenerHandle>>> =
        Arc::new(Mutex::new(None));

    // TODO: rewrite this into good code
    // TODO: handle shutdown
    connect_button.add_event_listener(move |_: ClickEvent| {
        let btn_recv_handle = button_receive_event_handle.clone();
        let btn_recv_handle2 = button_receive_event_handle.clone();
        let btn_recv_handle3 = button_receive_event_handle.clone();
        let btn_send_handle = button_send_event_handle.clone();
        let btn_send_handle2 = button_send_event_handle.clone();
        let btn_send_handle3 = button_send_event_handle.clone();
        let mut lock = btn_recv_handle.lock().unwrap();
        console!(
            log,
            "Closing old connection (not correctly implemented yet)!"
        );
        if let Some(handle) = (*lock).take() {
            handle.remove();
        }
        let mut lock2 = btn_send_handle.lock().unwrap();
        if let Some(handle) = (*lock2).take() {
            handle.remove();
        }
        console!(log, "Establishing connection...");
        let address_elem: InputElement = select(".address").try_into().unwrap();
        let address = address_elem.raw_value();
        let future = WebSocket::new_with_protocols(&address, &["ot"])
            .into_future()
            .map(move |ws| {
                ws.add_event_listener(move |_: SocketCloseEvent| {
                    console!(log, "Connection closed!");
                    let btn_recv_handle = btn_recv_handle3.clone();
                    let mut lock = btn_recv_handle.lock().unwrap();
                    if let Some(handle) = (*lock).take() {
                        handle.remove();
                    }
                    let btn_send_handle = btn_send_handle3.clone();
                    let mut lock2 = btn_send_handle.lock().unwrap();
                    if let Some(handle) = (*lock2).take() {
                        handle.remove();
                    }
                    select(".connect").class_list().remove("connected").unwrap();
                });
                ws
            })
            .map_err(|e| Error::with_chain(e, "Connection error"))
            .and_then(WasmWebSocket::open)
            .map(move |ws| {
                select(".connect").class_list().add("connected").unwrap();

                console!(log, "Connection established!");
                let receive_button = select(".ot-receive-btn");
                let mut lock = btn_recv_handle2.lock().unwrap();
                let ws1 = ws.clone();
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

                let send_button = select(".ot-send-btn");
                let mut lock2 = btn_send_handle2.lock().unwrap();
                *lock2 = Some(send_button.add_event_listener(move |_: ClickEvent| {
                    let values_elem: InputElement = select(".ot-send-values").try_into().unwrap();
                    let values = values_elem
                        .raw_value()
                        .split(',')
                        .map(|s| String::from(s.trim()).into_bytes())
                        .collect();
                    send(ws1.clone(), values);
                }));
            })
            .recover(|e| {
                console!(error, format!("{}", e.display_chain()));
                error(&e);
                //Never
                //PromiseFuture::print_error_panic(format!("{}", e.display_chain()))
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
