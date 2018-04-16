/// corrupted communication channel to simulate an active adversary
use std::io;
use super::*;

fn empty_corruptor<S>(_: &mut S, _: &mut [u8])
where
    S: Default,
{
}
fn empty_eavesdropper<S>(_: &mut S, _: &[u8])
where
    S: Default,
{
}

pub struct CorruptedChannel<S: Default, C: BinaryReceive + BinarySend> {
    pub state: S,
    conn: C,
    pub eavesdropper: fn(&mut S, &[u8]),
    pub corruptor: fn(&mut S, &mut [u8]),
}

impl<S: Default, C: BinaryReceive + BinarySend> CorruptedChannel<S, C> {
    /// Returns a CorruptedChannel which only forwards the buffers
    pub fn default(conn: C) -> Self {
        CorruptedChannel {
            state: S::default(),
            conn: conn,
            eavesdropper: empty_eavesdropper,
            corruptor: empty_corruptor,
        }
    }

    /// Returns a CorruptedChannel which only eavesdrops
    pub fn new_eavesdrop(conn: C, initial_state: S, eavesdropper: fn(&mut S, &[u8])) -> Self {
        CorruptedChannel {
            state: initial_state,
            conn: conn,
            eavesdropper: eavesdropper,
            corruptor: empty_corruptor,
        }
    }

    /// Returns a CorruptedChannel which only corrupts
    pub fn new_corrupt(conn: C, initial_state: S, corruptor: fn(&mut S, &mut [u8])) -> Self {
        CorruptedChannel {
            state: initial_state,
            conn: conn,
            eavesdropper: empty_eavesdropper,
            corruptor: corruptor,
        }
    }

    pub fn new(
        conn: C,
        initial_state: S,
        eavesdropper: fn(&mut S, &[u8]),
        corruptor: fn(&mut S, &mut [u8]),
    ) -> Self {
        CorruptedChannel {
            state: initial_state,
            conn: conn,
            eavesdropper: eavesdropper,
            corruptor: corruptor,
        }
    }
}

impl<S: Default, C: BinaryReceive + BinarySend> BinaryReceive for CorruptedChannel<S, C> {
    fn receive(&mut self) -> Result<Vec<u8>, io::Error> {
        let mut v = self.conn.receive()?;
        (self.corruptor)(&mut self.state, &mut v);
        Ok(v)
    }
}

impl<S: Default, C: BinaryReceive + BinarySend> BinarySend for CorruptedChannel<S, C> {
    fn send(&mut self, data: &[u8]) -> Result<(), io::Error> {
        (self.eavesdropper)(&mut self.state, data);
        self.conn.send(data)
    }
}
