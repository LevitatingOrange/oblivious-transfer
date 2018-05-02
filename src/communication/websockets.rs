use errors::*;
use super::{BinaryReceive, BinarySend};
use std::io::{Read, Write};

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use tungstenite::{Message, protocol::WebSocket};

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
impl<S: Read + Write> BinarySend for WebSocket<S> {
    fn send(&mut self, data: &[u8]) -> Result<()> {
        let v = data.to_owned();
        self.write_message(Message::binary(v))?;
        Ok(())
    }
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
impl<S: Read + Write> BinaryReceive for WebSocket<S> {
    fn receive(&mut self) -> Result<Vec<u8>> {
        if let Message::Binary(v) = self.read_message()? {
            Ok(v)
        } else {
            Err(ErrorKind::CommunicationError.into())
        }
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use stdweb::traits::*;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use stdweb::unstable::TryInto;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use stdweb::web::{
    WebSocket,
};
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use std::vec::Vec;



#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
struct WasmWebSocket {
    ws: WebSocket,
    msg: Vec<Vec<u8>> 
}

