use futures::task::LocalWaker;
use std::sync::{Arc, Mutex};
use std::vec::Vec;
use stdweb::traits::*;
use stdweb::web::event::{SocketCloseEvent, SocketMessageEvent, SocketOpenEvent};
use stdweb::web::SocketBinaryType;
use stdweb::web::TypedArray;
use stdweb::web::WebSocket;
use failure::{Fallible, err_msg};
use futures::{Future, Poll};
use futures::prelude::*;
use std::pin::Pin;
use std::io::ErrorKind;

macro_rules! enclose {
    ( ($( $x:ident ),*) $y:expr ) => {
        {
            $(let $x = $x.clone();)*
            $y
        }
    };
}

/// This is a wrapper around stdweb's websockets so we can use them
/// with futures (websockets in the browser are callback-based and do not implement
/// promises from the get-go)
pub struct WasmWebSocket {
    //me: Weak<Mutex<WasmWebSocket<'a>>>,
    ws: WebSocket,
    msg_buf: Fallible<Vec<u8>>,
    // TODO: only one waker, has to be list
    waker: Option<LocalWaker>,
    open: bool,
}

impl WasmWebSocket {
    fn new(ws: WebSocket) -> Arc<Mutex<WasmWebSocket>> {
        //let me: Weak<Mutex<WasmWebSocket<'a>>> = Weak::new();
        let s = Arc::new(Mutex::new(WasmWebSocket {
            //me: me,
            ws: ws,
            msg_buf: Ok(Vec::new()),
            waker: None,
            open: false,
        }));
        {
        //let mut me = s.lock().unwrap();
        //me.me = Arc::downgrade(&s);
        }
        {
        let sel = s.lock().unwrap();
        sel.ws.add_event_listener(enclose! { (s) move |_: SocketOpenEvent| {
            let mut me = s.lock().unwrap();
            me.open = true;
            //me.wakers.iter().for_each(|waker| waker.wake());
            if let Some(ref waker) = me.waker {
                waker.wake();
            }
        }});
        sel.ws.add_event_listener(enclose! { (s) move |event: SocketMessageEvent| {
            let data = event.data();
            let mut me = s.lock().unwrap();
            if let Some(arr) = data.into_array_buffer() {
                let buf: TypedArray<u8> = TypedArray::from(arr);
                if let Ok(ref mut msg_buf) = me.msg_buf {
                    let mut v = buf.to_vec();
                    v.reverse();
                    msg_buf.append(&mut v);
                }
                //me.wakers.iter().for_each(|waker| waker.wake());
                else {
                    me.msg_buf = Err(err_msg("Did not receive binary data!"));
                }
                if let Some(ref waker) = me.waker {
                    waker.wake();
                }
            }
        }});
        sel.ws.add_event_listener(enclose! { (s) move |event: SocketCloseEvent| {
            let mut me = s.lock().unwrap();
            me.msg_buf = Err(err_msg(event.reason()));
            //me.wakers.iter().for_each(|waker| waker.wake());
            if let Some(ref waker) = me.waker {
                waker.wake();
            }
        }});
        }
        s
    }

    pub fn open(socket: WebSocket) -> WasmWebSocketOpen {
        socket.set_binary_type(SocketBinaryType::ArrayBuffer);
        let ws = Self::new(socket);
        WasmWebSocketOpen { ws: ws }
    }
}

impl Drop for WasmWebSocket {
    fn drop(&mut self) {
        // TODO what if ws is already closed? Does this blow up?
        // TODO doesnt get called in browser example
        self.ws.close();
    }
}

pub struct WasmWebSocketOpen {
    ws: Arc<Mutex<WasmWebSocket>>,
}

impl Future for WasmWebSocketOpen {
    type Output = Arc<Mutex<WasmWebSocket>>;
    fn poll(self: Pin<&mut Self>, lw: &LocalWaker) ->  Poll<Self::Output> {
        let mut me = self.ws.lock().unwrap();
        if me.open {
            me.waker = None;
            return Poll::Ready(self.ws.clone());
        } else {
            me.waker = Some(lw.clone());
            return Poll::Pending;
        }
    }
}

pub struct WasmWebSocketAsyncRead {
    ws: Arc<Mutex<WasmWebSocket>>,
}

impl AsyncRead for WasmWebSocketAsyncRead {

    fn poll_read(&mut self, lw: &LocalWaker, buf: &mut [u8]) -> Poll<Result<usize, std::io::Error>> {
        let mut ws = self.ws.lock().unwrap();
        ws.waker = None;
        if let Ok(ref mut msg_buf) = ws.msg_buf {
            if msg_buf.len() > 0 {
                for i in 0..buf.len() {
                    if (msg_buf.len() as i64 - i as i64) < 0 {
                        let l = msg_buf.len();
                        msg_buf.truncate(0);
                        return Poll::Ready(Ok(l))
                    }
                    buf[i] = msg_buf[msg_buf.len() - i - 1];
                }
                msg_buf.truncate(msg_buf.len() - buf.len());
                return Poll::Ready(Ok(buf.len()))
            }
        } else {
            return Poll::Ready(Err(ErrorKind::Other.into()));
        }
        ws.waker = Some(lw.clone());
        Poll::Pending 
    }
}

// As webstd websocket returns instantly after send,
// this is only a wrapper so the interface is consistent for read and write
pub struct WasmWebSocketAsyncWrite {
    ws: Arc<Mutex<WasmWebSocket>>,
}

impl AsyncWrite for WasmWebSocketAsyncWrite {

    fn poll_write(&mut self, _: &LocalWaker,  buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
        if let Ok(ref mut ws) = self.ws.lock() {
            let arr = TypedArray::from(buf);
            Poll::Ready(ws.ws
                .send_array_buffer(&arr.buffer()))
                .map_err(|_| ErrorKind::ConnectionReset.into())
                .map_ok(|_| buf.len())
        } else {
            Poll::Ready(Err(ErrorKind::Other.into()))
        }
    }

    fn poll_flush(&mut self, _: &LocalWaker) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(&mut self, _: &LocalWaker) -> Poll<Result<(), std::io::Error>> {
        self.ws.lock().unwrap().ws.close();
        Poll::Ready(Ok(()))
    }
}
