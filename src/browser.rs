extern crate futures;
#[macro_use]
extern crate stdweb;
extern crate ot;
extern crate rand;
extern crate pcg_rand;
extern crate sha3;

use futures::prelude::*;
use ot::communication::async::websockets::*;
use ot::base_ot::async::chou::ChouOrlandiOTReceiver;
use ot::crypto::dummy::DummyCryptoProvider;
use sha3::Sha3_256;
use stdweb::PromiseFuture;
use rand::Rng;
use pcg_rand::Pcg32;

fn main() {
    stdweb::initialize();

    // TODO: is this rng secure? Read the crate doc and about pcgs
    let mut rng = Pcg32::new_unseeded();

    let future = WasmWebSocket::open("ws://127.0.0.1:3012")
        .unwrap()
        .and_then(move |ws| 
            ChouOrlandiOTReceiver::new(ws, Sha3_256::default(), DummyCryptoProvider::default(), rng)
        )
        .and_then(|s|
            //s.compute_key(3)
            s.receive(3, 4)
        )
        .map(|result| console!(log, format!("{:?}", result)))
        .map_err(|e| PromiseFuture::print_error_panic(format!("{}", e)));
    PromiseFuture::spawn_local(future);
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

