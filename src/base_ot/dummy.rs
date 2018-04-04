use std::io::prelude::*;
use std::mem;
use std::io;

pub struct DummyOT<T: Read + Write> {
    conn: T
}

impl <T: Read + Write> DummyOT<T> {
    pub fn new(conn: T) -> Result<Self, super::Error> {
        Ok(DummyOT {conn: conn})
    }
}

fn send_int<T: Write>(val: u64, conn: &mut T) -> Result<(), io::Error> {
    let buf: [u8; 8] = unsafe {
        mem::transmute(val)
    };
    conn.write(&buf)?;
    Ok(())
}

fn recv_int<T: Read>(conn: &mut T) -> Result<(u64), io::Error> {
    let mut buf = [0; 8];
    conn.read(&mut buf)?;
    Ok(unsafe {
        mem::transmute(buf)
    })
}

/// A simple dummy oblivious transfer routine, 1-to-n, of values of type i64. No security whatsoever.
impl <T: Read + Write> super::BaseOT<i64> for DummyOT<T> {
    fn send(&mut self, values: Vec<i64>) -> Result<(), super::Error> {
        let index = recv_int(&mut self.conn)?;
        if (index as usize) >= values.len() {
            return Err(super::Error::IndexOutOfRange)
        }
        send_int(values[index as usize] as u64, &mut self.conn)?;
        Ok(())
    }
    fn receive(&mut self, index: u64) -> Result<i64, super::Error> {
        send_int(index, &mut self.conn)?;
        let result = recv_int(&mut self.conn)? as i64;
        Ok(result)
    }  
}

#[cfg(test)]
mod tests {
    use super::DummyOT;
    use ::base_ot::BaseOT;
    use std::net::TcpListener;
    use std::net::TcpStream;
    use std::thread;
    #[test]
    fn dummy_ot_works() {
        let server = thread::spawn(move || {
            let mut ot = DummyOT::new(TcpListener::bind("127.0.0.1:1234").unwrap().accept().unwrap().0).unwrap();
            let _ = ot.send(vec![36, 7, 2, 10, 6, 0]).unwrap();
        });
        let client = thread::spawn(move || {
            let mut ot = DummyOT::new(TcpStream::connect("127.0.0.1:1234").unwrap()).unwrap();
            let val = ot.receive(3).unwrap();
            assert_eq!(val, 10);
        });
        server.join().unwrap();
        client.join().unwrap();
    } 
    #[test]
    #[should_panic]
    fn dummy_index_too_large() {
        let server = thread::spawn(move || {
            let mut ot = DummyOT::new(TcpListener::bind("127.0.0.1:1235").unwrap().accept().unwrap().0).unwrap();
            let _ = ot.send(vec![36, 7, 2, 10, 6, 0]).unwrap();
        });
        let client = thread::spawn(move || {
            let mut ot = DummyOT::new(TcpStream::connect("127.0.0.1:1235").unwrap()).unwrap();
            let _ = ot.receive(6).unwrap();
        });
        server.join().unwrap();
        client.join().unwrap();
    }
}