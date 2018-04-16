use errors::*;
use tungstenite::{Message, protocol::WebSocket};
use super::{BinaryReceive, BinarySend};
use std::net::TcpStream;

impl BinarySend for WebSocket<TcpStream> {
    fn send(&mut self, data: &[u8]) -> Result<()> {
        let v = data.to_owned();
        self.write_message(Message::binary(v))?;
        Ok(())
    }
}

impl BinaryReceive for WebSocket<TcpStream> {
    fn receive(&mut self) -> Result<Vec<u8>> {
        if let Message::Binary(v) = self.read_message()? {
            Ok(v)
        } else {
            Err(ErrorKind::CommunicationError.into())
        }
    }
}
