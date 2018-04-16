use errors::*;
use tungstenite::{Message, protocol::WebSocket};
use super::{BinaryReceive, BinarySend};
use std::io::{Read, Write};

impl<S: Read + Write> BinarySend for WebSocket<S> {
    fn send(&mut self, data: &[u8]) -> Result<()> {
        let v = data.to_owned();
        self.write_message(Message::binary(v))?;
        Ok(())
    }
}

impl<S: Read + Write> BinaryReceive for WebSocket<S> {
    fn receive(&mut self) -> Result<Vec<u8>> {
        if let Message::Binary(v) = self.read_message()? {
            Ok(v)
        } else {
            Err(ErrorKind::CommunicationError.into())
        }
    }
}
