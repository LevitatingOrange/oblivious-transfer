extern crate futures;
#[macro_use]
extern crate stdweb;
extern crate error_chain;
#[macro_use]
extern crate ot;
extern crate rand;
extern crate tiny_keccak;

use error_chain::ChainedError;
use futures::prelude::*;
use ot::async::base_ot::chou::{ChouOrlandiOTReceiver, ChouOrlandiOTSender};
//use ot::async::base_ot::{BaseOTReceiver, BaseOTSender};
use ot::async::communication::websockets::*;
//use ot::async::communication::{BinaryReceive, BinarySend};
use ot::async::communication::{GetConn};
use ot::async::crypto::aes_browser::AesCryptoProvider;
use ot::async::ot_extension::iknp::{IKNPExtendedOTReceiver, IKNPExtendedOTSender};
use ot::async::ot_extension::{ExtendedOTReceiver, ExtendedOTSender};
use ot::common::digest::sha3::SHA3_256;
use ot::common::util::{generate_random_choices, generate_random_string_pairs};
use ot::errors::*;
use rand::{ChaChaRng, SeedableRng};
// use std::sync::{Arc, Mutex};
//use stdweb::traits::*;
use stdweb::unstable::TryInto;
// use stdweb::web::event::{ClickEvent, SocketCloseEvent};
// use stdweb::web::html_element::InputElement;
// use stdweb::web::EventListenerHandle;
use stdweb::web::TypedArray;
use stdweb::web::WebSocket;
// use stdweb::web::{document, Element, HtmlElement};
use std::result;
use std::string;
use stdweb::PromiseFuture;
// fn select(sel: &str) -> Element {
//     document().query_selector(sel).unwrap().unwrap()
// }

// fn print_received_value(val: String) {
//     let parent: HtmlElement = select(".ot-receive").try_into().unwrap();
//     let elem: HtmlElement = document()
//         .create_element("div")
//         .unwrap()
//         .try_into()
//         .unwrap();
//     elem.class_list().add("row").unwrap();
//     elem.set_text_content(&val);
//     parent.append_child(&elem);
// }

// fn error(val: &Error) {
//     let err_div: HtmlElement = select(".error").try_into().unwrap();
//     err_div.class_list().add("error-visible").unwrap();
//     err_div.set_text_content(val.description());
// }

// fn receive(ws: Arc<Mutex<WasmWebSocket>>, c: usize, n: usize) {
//     // TODO: is this rng secure? Read the crate doc and about pcgs
//     // TODO: make example with single Receiver that it used more than once, fix it first
//     let handle = ws.clone();
//     let lock = handle.lock().unwrap();
//     console!(log, "Trying to receive value...");
//     let seed: TypedArray<u8> = js!{
//         var array = new Uint8Array(32);
//         window.crypto.getRandomValues(array);
//         return array;
//     }.try_into()
//         .unwrap();
//     let mut seed_arr: [u8; 32] = Default::default();
//     seed_arr.copy_from_slice(&seed.to_vec());
//     let rng = ChaChaRng::from_seed(seed_arr);
//     let future = lock
//         .send("send".as_bytes().to_owned())
//         .and_then(move |_| {
//             ChouOrlandiOTReceiver::new(ws, SHA3_256::default(), AesCryptoProvider::default(), rng)
//         })
//         .and_then(move |s| s.receive(c, n))
//         .and_then(|(result, _)| {
//             String::from_utf8(result)
//                 .map_err(|e| Error::with_chain(e, "Error while parsing String"))
//         })
//         .map(move |result| {
//             console!(log, "Value received!");
//             print_received_value(result)
//         })
//         .recover(|e| {
//             console!(error, format!("{}", e.display_chain()));
//             if let Some(ref backtrace) = e.backtrace() {
//                 console!(error, format!("Backtrace: {:?}", backtrace));
//             }
//             error(&e);
//         });
//     PromiseFuture::spawn_local(future);
// }

// fn send(ws: Arc<Mutex<WasmWebSocket>>, values: Vec<Vec<u8>>) {
//     let handle = ws.clone();
//     let lock = handle.lock().unwrap();
//     console!(log, "Trying to send values...");
//     let seed: TypedArray<u8> = js!{
//         var array = new Uint8Array(32);
//         window.crypto.getRandomValues(array);
//         return array;
//     }.try_into()
//         .unwrap();
//     let mut seed_arr: [u8; 32] = Default::default();
//     seed_arr.copy_from_slice(&seed.to_vec());
//     let rng = ChaChaRng::from_seed(seed_arr);
//     let future = lock
//         .send("receive".as_bytes().to_owned())
//         .and_then(move |_| {
//             ChouOrlandiOTSender::new(ws, SHA3_256::default(), AesCryptoProvider::default(), rng)
//         })
//         .and_then(move |s| s.send(values))
//         .map(|_| console!(log, "values sent!"))
//         .recover(|e| {
//             console!(error, format!("{}", e.display_chain()));
//             if let Some(ref backtrace) = e.backtrace() {
//                 console!(error, format!("Backtrace: {:?}", backtrace));
//             }
//             error(&e);
//         });
//     PromiseFuture::spawn_local(future);
// }

// fn main() {
//     stdweb::initialize();

//     let connect_button = select(".connect-btn");

//     let button_receive_event_handle: Arc<Mutex<Option<EventListenerHandle>>> =
//         Arc::new(Mutex::new(None));
//     let button_send_event_handle: Arc<Mutex<Option<EventListenerHandle>>> =
//         Arc::new(Mutex::new(None));

//     // TODO: rewrite this into good code
//     // TODO: handle shutdown
//     connect_button.add_event_listener(move |_: ClickEvent| {
//         let btn_recv_handle = button_receive_event_handle.clone();
//         let btn_recv_handle2 = button_receive_event_handle.clone();
//         let btn_recv_handle3 = button_receive_event_handle.clone();
//         let btn_send_handle = button_send_event_handle.clone();
//         let btn_send_handle2 = button_send_event_handle.clone();
//         let btn_send_handle3 = button_send_event_handle.clone();
//         let mut lock = btn_recv_handle.lock().unwrap();
//         console!(
//             log,
//             "Closing old connection (not correctly implemented yet)!"
//         );
//         if let Some(handle) = (*lock).take() {
//             handle.remove();
//         }
//         let mut lock2 = btn_send_handle.lock().unwrap();
//         if let Some(handle) = (*lock2).take() {
//             handle.remove();
//         }
//         console!(log, "Establishing connection...");
//         let address_elem: InputElement = select(".address").try_into().unwrap();
//         let address = address_elem.raw_value();
//         let future = WebSocket::new_with_protocols(&address, &["ot"])
//             .into_future()
//             .map(move |ws| {
//                 ws.add_event_listener(move |_: SocketCloseEvent| {
//                     console!(log, "Connection closed!");
//                     let btn_recv_handle = btn_recv_handle3.clone();
//                     let mut lock = btn_recv_handle.lock().unwrap();
//                     if let Some(handle) = (*lock).take() {
//                         handle.remove();
//                     }
//                     let btn_send_handle = btn_send_handle3.clone();
//                     let mut lock2 = btn_send_handle.lock().unwrap();
//                     if let Some(handle) = (*lock2).take() {
//                         handle.remove();
//                     }
//                     select(".connect").class_list().remove("connected").unwrap();
//                 });
//                 ws
//             })
//             .map_err(|e| Error::with_chain(e, "Connection error"))
//             .and_then(WasmWebSocket::open)
//             .map(move |ws| {
//                 select(".connect").class_list().add("connected").unwrap();

//                 console!(log, "Connection established!");
//                 let receive_button = select(".ot-receive-btn");
//                 let mut lock = btn_recv_handle2.lock().unwrap();
//                 let ws1 = ws.clone();
//                 *lock = Some(receive_button.add_event_listener(move |_: ClickEvent| {
//                     let index_elem: InputElement = select(".ot-receive-index").try_into().unwrap();
//                     let len_elem: InputElement = select(".ot-receive-len").try_into().unwrap();
//                     let index: usize = index_elem
//                         .raw_value()
//                         .parse()
//                         .map_err(|e| Error::with_chain(e, "couldn't parse index"))
//                         .map_err(|e| error(&e))
//                         .unwrap();
//                     let len: usize = len_elem
//                         .raw_value()
//                         .parse()
//                         .map_err(|e| Error::with_chain(e, "couldn't parse length"))
//                         .map_err(|e| error(&e))
//                         .unwrap();
//                     receive(ws.clone(), index, len);
//                 }));

//                 let send_button = select(".ot-send-btn");
//                 let mut lock2 = btn_send_handle2.lock().unwrap();
//                 *lock2 = Some(send_button.add_event_listener(move |_: ClickEvent| {
//                     let values_elem: InputElement = select(".ot-send-values").try_into().unwrap();
//                     let values = values_elem
//                         .raw_value()
//                         .split(',')
//                         .map(|s| String::from(s.trim()).into_bytes())
//                         .collect();
//                     send(ws1.clone(), values);
//                 }));
//             })
//             .recover(|e| {
//                 console!(error, format!("{}", e.display_chain()));
//                 error(&e);
//                 //Never
//                 //PromiseFuture::print_error_panic(format!("{}", e.display_chain()))
//             });
//         PromiseFuture::spawn_local(future);
//     });

//     stdweb::event_loop();
// }

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
