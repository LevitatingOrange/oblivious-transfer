/// chou and orlandis 1-out-of-n OT
/// for all following explanations consider [https://eprint.iacr.org/2015/267.pdf] as source

use std::io::prelude::*;
use rand::Rng;
use curve25519_dalek::edwards::*;
use curve25519_dalek::scalar::*;
use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE, EIGHT_TORSION};
use std::vec::Vec;
use digest::Digest;
use digest::generic_array::{GenericArray, ArrayLength};


pub struct ChouOrlandiOTSender<T: Read + Write> {
    conn: T,
    y: Scalar,
    t64: EdwardsPoint,
    s8: EdwardsPoint
}

fn receive_point<T>(conn: &mut T) -> Result<EdwardsPoint, super::Error> where T: Read {
    let mut buf: [u8; 32] = [0; 32];
    conn.read_exact(&mut buf)?;
    CompressedEdwardsY(buf).decompress().ok_or(super::Error::PointError)
}


impl <T: Read + Write> ChouOrlandiOTSender <T> {
    pub fn new<R>(mut conn: T, rng: &mut R) -> Result<Self, super::Error> where R:Rng {
        let y = Scalar::random(rng);
        let mut s = &y * &ED25519_BASEPOINT_TABLE;

        // we dont send s directly, instead we add a point from the eight torsion subgroup.
        // This enables the receiver to verify that s is in the subgroup of the twisted edwards curve 
        // 25519 of Bernstein et al. [TODO: CITE]
        conn.write((s + EIGHT_TORSION[1]).compress().as_bytes())?;
        // see ChouOrlandiOTReceiver::new for discussion of why to multiply by the cofactor (i.e. 8)
        // FIXME: do we need this? and if, then we can't use *= !!!
        // also look at compute_keys' use of y
        // y *= eight;
        s = s.mul_by_cofactor();
        Ok(ChouOrlandiOTSender {conn: conn, y: y, t64: (y * s).mul_by_cofactor(), s8: s})
    }
    
    pub fn compute_keys<D, E>(&mut self, n: u64, mut hasher: D) -> Result<Vec<GenericArray<u8, E>>, super::Error> where 
    D: Digest<OutputSize = E> + Clone, E: ArrayLength<u8> {
        let r = receive_point(&mut self.conn)?.mul_by_cofactor();
        // see ChouOrlandiOTReceiver::new for a discussion for why this is needed
        // seed the hash function with s and r in its compressed form
        hasher.input(self.s8.compress().as_bytes());
        hasher.input(r.compress().as_bytes());
        Ok((0..n).map(|j| {
            // hash p=64yR - 64jT, this will reduce to 64xS if y == j, but as x is only known 
            // to the receiver (provided the discrete logartihm problem is hard in our curve)
            // the sender does not know which p is the correct one (i.e. the one the receiver owns).
            let p = self.y * r - Scalar::from_u64(j) * self.t64;
            let mut hasher = hasher.clone();
            hasher.input(p.compress().as_bytes());
            hasher.result()
        }).collect())
    }
}

pub struct ChouOrlandiOTReceiver<T: Read + Write, R: Rng> {
    conn: T,
    rng: R,
    s8: EdwardsPoint
}


impl <T: Read + Write, R: Rng> ChouOrlandiOTReceiver <T, R> {
    pub fn new(mut conn: T, rng: R) -> Result<Self, super::Error> {
        let mut s = receive_point(&mut conn)?;

        // as we've added a point from the eight torsion subgroup to s before sending, 
        // by multiplying with the cofactor (i.e. 8, i.e. the order of the eight torsion subgroup)
        // we get [8]s and can be sure that the received value is indeed in the subgroup
        // of our 25519 twisted edwards curve [TODO: Cite]
        s = s.mul_by_cofactor();

        Ok(ChouOrlandiOTReceiver {conn: conn, rng: rng, s8: s})
    }

    pub fn compute_key<D, E>(&mut self, c: u64, mut hasher: D) -> Result<GenericArray<u8, E>, super::Error> where 
    D: Digest<OutputSize = E> + Clone, E: ArrayLength<u8> {
        let x = Scalar::random(&mut self.rng);
        let r = Scalar::from_u64(c) * self.s8 + (&x * &ED25519_BASEPOINT_TABLE).mul_by_cofactor();
        self.conn.write((r + EIGHT_TORSION[1]).compress().as_bytes())?;
        // seed the hash function with s and r in it's compressed form

        hasher.input(self.s8.compress().as_bytes());
        hasher.input(r.mul_by_cofactor().compress().as_bytes());

        // hash p = 64xS
        // TODO: is it better use mul_by_cofactor?
        let p = (x * Scalar::from_u64(8)) * self.s8;
        hasher.input(p.compress().as_bytes());
        Ok(hasher.result())
    }
}



#[cfg(test)]
mod tests {
    use rand::OsRng;
    use super::*;
    use std::net::TcpListener;
    use std::net::TcpStream;
    use std::thread;
    use sha3::Sha3_256;

    // TODO test for vuln mentioned in paper

    #[test]
    fn chou_ot_key_exchange() {
        let index = 3;
        let server = thread::spawn(move || {
            let mut ot = ChouOrlandiOTSender::new(TcpListener::bind("127.0.0.1:1236").unwrap().accept().unwrap().0, &mut OsRng::new().unwrap()).unwrap();
            ot.compute_keys(10, Sha3_256::default()).unwrap()
        });
        let client = thread::spawn(move || {
            let mut ot = ChouOrlandiOTReceiver::new(TcpStream::connect("127.0.0.1:1236").unwrap(), OsRng::new().unwrap()).unwrap();
            ot.compute_key(index, Sha3_256::default()).unwrap()
        });
        let hashes_sender = server.join().unwrap();
        let hash_receiver = client.join().unwrap();

        assert_eq!(hashes_sender[index as usize], hash_receiver);
    }

    #[test]
    fn chou_ot_key_exchange_multiple() {
        static indices: [u64; 5] = [5, 0, 9, 3, 7];

        let server = thread::spawn(move || {
            let mut ot = ChouOrlandiOTSender::new(TcpListener::bind("127.0.0.1:1237").unwrap().accept().unwrap().0, &mut OsRng::new().unwrap()).unwrap();
            indices.iter().map(move |i| ot.compute_keys(10, Sha3_256::default()).unwrap()[*i as usize]).collect()
        });
        let client = thread::spawn(move || {
            let mut ot = ChouOrlandiOTReceiver::new(TcpStream::connect("127.0.0.1:1237").unwrap(), OsRng::new().unwrap()).unwrap();
            indices.iter().map(move |i| ot.compute_key(*i, Sha3_256::default()).unwrap()).collect()
        });
        
        let hashes_sender:Vec<_> = server.join().unwrap();
        let hashes_receiver:Vec<_> = client.join().unwrap();

        for (send_hash, recv_hash) in hashes_sender.iter().zip(hashes_receiver.iter()) {
            assert_eq!(send_hash, recv_hash);
        }
    } 
}