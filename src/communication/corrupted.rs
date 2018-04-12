/// corrupted communication channel to simulate an active adversary
use std::io::prelude::*;
use std::io;

fn empty_corruptor<S>(_: &mut S, buf: &mut [u8])
where S: Default {
}
fn empty_eavesdropper<S>(_: &mut S, buf: &[u8])
where S: Default {
}

struct CorruptedChannel<S: Default, C: Read + Write> {
    pub state: S, 
    conn: C, 
    pub eavesdropper: fn(&mut S, &[u8]),
    pub corruptor: fn(&mut S, &mut [u8])
}

impl <S: Default, C: Read + Write> CorruptedChannel<S, C> {
    /// Returns a CorruptedChannel which only forwards the buffers 
    pub fn default(conn: C) -> Self {
        CorruptedChannel {state: S::default(), conn: conn, eavesdropper: empty_eavesdropper, corruptor: empty_corruptor}
    }
    
    pub fn new(conn: C, initial_state: S, 
    eavesdropper: fn(&mut S, &[u8]), corruptor: fn(&mut S, &mut [u8])) -> Self {
        CorruptedChannel {state: S::default(), conn: conn, eavesdropper: eavesdropper, corruptor: corruptor}
    }
}

impl <S: Default, C: Read + Write> Read for CorruptedChannel<S, C> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        (self.corruptor)(&mut self.state, buf);
        self.conn.write(buf)
    }
}

impl <S: Default, C: Read + Write> Read for CorruptedChannel<S, C> {
    fn write(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        (self.corruptor)(&mut self.state, buf);
        self.conn.write(buf)
    }
}

