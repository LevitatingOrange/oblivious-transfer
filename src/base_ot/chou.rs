/// chou and orlandis 1-out-of-n OT
/// for all following explanations consider [https://eprint.iacr.org/2015/267.pdf] as source

use std::io::prelude::*;
use rand::{OsRng, Rng};
use curve25519_dalek::edwards::*;
use curve25519_dalek::scalar::*;
use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE, EIGHT_TORSION};
use std::vec::Vec;
use digest::Digest;
use digest::generic_array::{GenericArray, ArrayLength};


pub struct ChouOrlandiOTSender<T: Read + Write> {
    conn: T,
    y: Scalar,
    t: EdwardsPoint,
    s: EdwardsPoint
}

fn receive_point<T>(conn: &mut T) -> Result<EdwardsPoint, super::Error> where T: Read {
    let mut buf: [u8; 32] = [0; 32];
    conn.read_exact(&mut buf)?;
    CompressedEdwardsY(buf).decompress().ok_or(super::Error::PointError)
}


impl <T: Read + Write> ChouOrlandiOTSender <T> {
    fn new<R>(mut conn: T, rng: &mut R) -> Result<Self, super::Error> where R:Rng {
        let y = Scalar::random(rng);
        let mut s = &y * &ED25519_BASEPOINT_TABLE;

        // we dont send s directly, instead we add a point from the eight torsion subgroup.
        // This enables the receiver to verify that s is in the subgroup of the twisted edwards curve 
        // 25519 of Bernstein et al. [TODO: CITE]
        conn.write((s + EIGHT_TORSION[0]).compress().as_bytes())?;
        // see ChouOrlandiOTReceiver::new for discussion of why to multiply by the cofactor (i.e. 8)
        // FIXME: do we need this? and if, then we can't use *= !!!
        // also look at compute_keys' use of y
        // y *= eight;
        s = s.mul_by_cofactor();
        Ok(ChouOrlandiOTSender {conn: conn, y: y, t: (y * s).mul_by_cofactor(), s: s})
    }
    
    fn compute_keys<D, E>(&mut self, n: u64, mut hasher: D) -> Result<Vec<GenericArray<u8, E>>, super::Error> where 
    D: Digest<OutputSize = E> + Clone, E: ArrayLength<u8> {
        let mut r = receive_point(&mut self.conn)?;
        // see ChouOrlandiOTReceiver::new for a discussion for why this is needed
        r = r.mul_by_cofactor();
        // seed the hash function with s and r in its compressed form
        hasher.input(self.s.compress().as_bytes());
        hasher.input(r.compress().as_bytes());
        Ok((0..n).map(|j| {
            // hash p=yR - jT, this will reduce to xS if y == j, but as x is only known 
            // to the receiver (provided the discrete logartihm problem is hard in our curve)
            // the sender does not know which p is the correct one (i.e. the one the receiver owns).
            let p = self.y * r - Scalar::from_u64(j) * self.t;
            let mut hasher = hasher.clone();
            hasher.input(p.compress().as_bytes());
            hasher.result()
        }).collect())
    }
}

pub struct ChouOrlandiOTReceiver<T: Read + Write, R: Rng> {
    conn: T,
    rng: R,
    s: EdwardsPoint
}


impl <T: Read + Write, R: Rng> ChouOrlandiOTReceiver <T, R> {
    fn new(mut conn: T, rng: R) -> Result<Self, super::Error> {
        let mut s = receive_point(&mut conn)?;

        // as we've added a point from the eight torsion subgroup to s before sending, 
        // by multiplying with the cofactor (i.e. 8, i.e. the order of the eight torsion subgroup)
        // we get [8]s and can be sure that the received value is indeed in the subgroup
        // of our 25519 twisted edwards curve [TODO: Cite]
        s = s.mul_by_cofactor();

        Ok(ChouOrlandiOTReceiver {conn: conn, rng: rng, s: s})
    }

    fn compute_keys<D, E>(&mut self, n: u64, mut hasher: D) -> Result<GenericArray<u8, E>, super::Error> where 
    D: Digest<OutputSize = E> + Clone, E: ArrayLength<u8> {
        let mut r = receive_point(&mut self.conn)?;
        // see ChouOrlandiOTReceiver::new for a discussion for why this is needed
        r = r.mul_by_cofactor();
        // seed the hash function with s and r in its compressed form

        hasher.input(self.s.compress().as_bytes());
        hasher.input(r.compress().as_bytes());
        unimplemented!()
    }
}



