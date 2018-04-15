/// corrupted communication channel to simulate an active adversary
use std::io::prelude::*;
use std::io;

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

pub struct CorruptedChannel<S: Default, C: Read + Write> {
    pub state: S,
    conn: C,
    pub eavesdropper: fn(&mut S, &[u8]),
    pub corruptor: fn(&mut S, &mut [u8]),
}

impl<S: Default, C: Read + Write> CorruptedChannel<S, C> {
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

impl<S: Default, C: Read + Write> Read for CorruptedChannel<S, C> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        (self.corruptor)(&mut self.state, buf);
        self.conn.read(buf)
    }
}

impl<S: Default, C: Read + Write> Write for CorruptedChannel<S, C> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        (self.eavesdropper)(&mut self.state, buf);
        self.conn.write(buf)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.conn.flush()
    }
}
