use errors::*;
use futures::prelude::task::{Context, Waker};
use futures::prelude::*;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::{Rc, Weak};
use std::vec::Vec;
use stdweb::traits::*;
use stdweb::unstable::TryInto;
use stdweb::web::WebSocket;
use stdweb::web::{ArrayBuffer, TypedArray};

use stdweb::web::event::{SocketCloseEvent, SocketErrorEvent, SocketMessageEvent, SocketOpenEvent};

struct WasmWebSocket {
    me: Weak<WasmWebSocket>,
    ws: WebSocket,
    // TODO: what happens when we get values from different calculations?
    msg_queue: RefCell<Result<VecDeque<Vec<u8>>>>,
    waker: Option<Waker>,
}

impl WasmWebSocket {
    fn new(ws: WebSocket) -> Self {
        let me: Weak<WasmWebSocket> = Weak::new();
        let handle1 = me.clone();
        let handle2 = me.clone();
        ws.add_event_listener(move |event: SocketMessageEvent| {
            let data = event.data();
            if let Some(arr) = data.into_array_buffer() {
                if let Some(me) = handle1.clone().upgrade() {
                    let buf: TypedArray<u8> = TypedArray::from(arr);
                    if let Ok(ref mut msg_queue) = *me.msg_queue.borrow_mut() {
                        msg_queue.push_back(buf.to_vec());
                    }
                    //me.wakers.iter().for_each(|waker| waker.wake());
                    if let Some(ref waker) = me.waker {
                        waker.wake();
                    }
                }
            }
        });
        ws.add_event_listener(move |event: SocketCloseEvent| {
            if let Some(me) = handle2.clone().upgrade() {
                me.msg_queue.replace(Err(event.reason().into()));
                //me.wakers.iter().for_each(|waker| waker.wake());
                if let Some(ref waker) = me.waker {
                    waker.wake();
                }
            }
        });

        WasmWebSocket {
            me: me,
            ws: ws,
            msg_queue: RefCell::new(Ok(VecDeque::new())),
            waker: None,
        }
    }
}

impl Drop for WasmWebSocket {
    fn drop(&mut self) {
        // TODO what if ws is already closed? Does this blow up?
        self.ws.close();
    }
}

struct WasmWebSocketRead {
    ws: Option<WasmWebSocket>,
}

impl Future for WasmWebSocketRead {
    type Item = (WasmWebSocket, Vec<u8>);
    type Error = Error;


    fn poll(&mut self, cx: &mut Context) -> Result<Async<Self::Item>> {
        if let Some(mut ws) = self.ws.take() {
            // we can't return val directly because of the borrow of the msg_queue
            // it has to go out of scope first
            let mut val = None;
            // if our websocket encountered an error, it's msg_queue field will be of Err variant
            if let Ok(ref mut msg_queue) = *ws.msg_queue.borrow_mut() {
                // if there is data in our msg_queue we can return it
                val = msg_queue.pop_front();
            } else {
                bail!("Error reading from websocket")
            }
            if let Some(buf) = val {
                ws.waker = None;
                return Ok(Async::Ready((ws, buf)));
            } else {
                ws.waker = Some(cx.waker().clone());
                self.ws = Some(ws);
                return Ok(Async::Pending);
            }
        } else {
            bail!("Internal error, couldn't access websocket value. This should not happen")
        }
    }
}
