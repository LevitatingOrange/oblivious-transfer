use errors::*;
use futures::prelude::task::{Context, Waker};
use futures::prelude::*;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Weak};
use std::vec::Vec;
use stdweb::{console, __internal_console_unsafe, js, _js_impl, __js_raw_asm};
use stdweb::traits::*;
use stdweb::web::WebSocket;
use stdweb::web::{TypedArray};

use stdweb::web::event::{SocketCloseEvent, SocketMessageEvent, SocketOpenEvent};

pub struct WasmWebSocket {
    me: Weak<Mutex<WasmWebSocket>>,
    ws: WebSocket,
    // TODO: is it good to use owned vectors? (everywhere in the project)
    msg_queue: Result<VecDeque<Vec<u8>>>,
    waker: Option<Waker>,
    open: bool,
}

impl WasmWebSocket {
    fn new(ws: WebSocket) -> Arc<Mutex<Self>> {
        let me: Weak<Mutex<WasmWebSocket>> = Weak::new();
        let s = Arc::new(Mutex::new(WasmWebSocket {
            me: me,
            ws: ws,
            msg_queue: Ok(VecDeque::new()),
            waker: None,
            open: false,
        }));
        {
        let mut me = s.lock().unwrap();
        me.me = Arc::downgrade(&s);

        let handle0 = s.clone();
        let handle1 = s.clone();
        let handle2 = s.clone();
        me.ws.add_event_listener(move |_: SocketOpenEvent| {
            if let Ok(ref mut me) = handle0.lock() {
                me.open = true;
                //me.wakers.iter().for_each(|waker| waker.wake());
                if let Some(ref waker) = me.waker {
                    waker.wake();
                }
            }
        });
        me.ws.add_event_listener(move |event: SocketMessageEvent| {
            let data = event.data();
            if let Some(arr) = data.into_array_buffer() {
                if let Ok(ref mut me) = handle1.lock() {
                    let buf: TypedArray<u8> = TypedArray::from(arr);
                    if let Ok(ref mut msg_queue) = me.msg_queue {
                        msg_queue.push_back(buf.to_vec());
                    }
                    //me.wakers.iter().for_each(|waker| waker.wake());
                    if let Some(ref waker) = me.waker {
                        waker.wake();
                    }
                }
            }
        });
        me.ws.add_event_listener(move |event: SocketCloseEvent| {
                if let Ok(ref mut me) = handle2.lock() {
                    me.msg_queue = Err(event.reason().into());
                    //me.wakers.iter().for_each(|waker| waker.wake());
                    if let Some(ref waker) = me.waker {
                        waker.wake();
                    }
                }
        });
        }
        s
    }

    pub fn open(address: &str) -> Result<WasmWebSocketOpen> {
        let socket = WebSocket::new(address).map_err(|e| Error::with_chain(e, "Could not open websocket"))?;
        let ws = Self::new(socket);
        Ok(WasmWebSocketOpen { ws: ws })
    }

    pub fn read(&self) -> WasmWebSocketRead {
        WasmWebSocketRead { ws: self.me.upgrade().unwrap().clone() }
    }
    pub fn write(&self, buffer: Vec<u8>) -> WasmWebSocketWrite {
        WasmWebSocketWrite {
            ws: self.me.upgrade().unwrap().clone(),
            buffer: buffer,
        }
    }
}

impl Drop for WasmWebSocket {
    fn drop(&mut self) {
        // TODO what if ws is already closed? Does this blow up?
        self.ws.close();
    }
}

pub struct WasmWebSocketOpen {
    ws: Arc<Mutex<WasmWebSocket>>
}

impl Future for WasmWebSocketOpen {
    type Item = Arc<Mutex<WasmWebSocket>>;
    type Error = Error;
    fn poll(&mut self, cx: &mut Context) -> Result<Async<Self::Item>> {
        if let Ok(ref mut ws) = self.ws.lock() {
            if ws.open {
                ws.waker = None;
                return Ok(Async::Ready(self.ws.clone()));
            } else {
                ws.waker = Some(cx.waker().clone());
                return Ok(Async::Pending);
            }
        } else {
            bail!("Internal error, couldn't access mutex!")
        }
    }
}

pub struct WasmWebSocketRead {
    ws: Arc<Mutex<WasmWebSocket>>,
}

impl Future for WasmWebSocketRead {
    type Item = (Arc<Mutex<WasmWebSocket>>, Vec<u8>);
    type Error = Error;

    fn poll(&mut self, cx: &mut Context) -> Result<Async<Self::Item>> {
        if let Ok(ref mut ws) = self.ws.lock() {
            // we can't return val directly because of the borrow of the msg_queue
            // it has to go out of scope first

            let value = match ws.msg_queue {
                Ok(ref mut msg_queue) => {
                    msg_queue.pop_front()
                }
                // return returned error
                Err(_) => {return Err("Couldn't read from web socket".into())}
            };
            if let Some(buf) = value {
                ws.waker = None;
                return Ok(Async::Ready((self.ws.clone(), buf)));
            } else {
                ws.waker = Some(cx.waker().clone());
                return Ok(Async::Pending);
            }

        } else {
            bail!("Internal error, couldn't access websocket value. This should not happen")
        }
    }
}

// As webstd websocket returns instantly after send,
// this is only a wrapper so the interface is consistent for read and write
pub struct WasmWebSocketWrite {
    ws: Arc<Mutex<WasmWebSocket>>,
    buffer: Vec<u8>,
}

impl Future for WasmWebSocketWrite {
    type Item = Arc<Mutex<WasmWebSocket>>;
    type Error = Error;

    fn poll(&mut self, _cx: &mut Context) -> Result<Async<Self::Item>> {
        if let Ok(ref mut ws) = self.ws.lock() {
            let arr = TypedArray::from(self.buffer.as_slice());
            ws.ws
                .send_array_buffer(&arr.buffer())
                .map(|_| (Async::Ready(self.ws.clone())))
                .map_err(|e| Error::with_chain(e, "Could not send data over socket"))
        } else {
            bail!("Internal error, couldn't access websocket value. This should not happen")
        }
    }
}