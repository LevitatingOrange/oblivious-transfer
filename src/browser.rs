extern crate futures;
#[macro_use]
extern crate stdweb;
extern crate ot;

use futures::prelude::*;
use stdweb::PromiseFuture;
use ot::communication::async::websockets::*;

fn main() {
    stdweb::initialize();

    let msg = "Hello World".to_owned();
    let future = WasmWebSocket::open("ws://127.0.0.1:3012")
        .unwrap()
        .and_then(|ws| {
            let lock = ws.lock().unwrap();
            lock.write(msg.into_bytes())
        })
        .and_then(|ws| {
            let lock = ws.lock().unwrap();
            lock.read()
        })
        .map(|(_, result)| console!(log, String::from_utf8(result).unwrap()))
        .map_err(|e| PromiseFuture::print_error_panic(e.description()));
    PromiseFuture::spawn_local(future);
    stdweb::event_loop();
}
