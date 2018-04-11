/// chou and orlandis 1-out-of-n OT
/// for all following explanations consider [https://eprint.iacr.org/2015/267.pdf] as source

use std::io::prelude::*;
use rand::{OsRng, Rng};
use curve25519_dalek::edwards::*;
use curve25519_dalek::scalar::*;
use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, ED25519_BASEPOINT_TABLE, EIGHT_TORSION};


pub struct ChouOrlandiOTSender<T: Read + Write> {
    conn: T,
    y: Scalar,
    t: EdwardsPoint
}


impl <T: Read + Write> ChouOrlandiOTSender <T> {
    fn new<R>(mut conn: T, rng: &mut R) -> Result<Self, super::Error> where R:Rng {
        let y = Scalar::random(rng);
        let mut s = &y * &ED25519_BASEPOINT_TABLE;

        // we dont send s directly, instead we add an point form the eight torsion subgroup.
        // This enables the receiver to verify that s is in the subgroup of the twisted edwards curve 
        // 25519 of Bernstein et al. [TODO: CITE]
        conn.write((s + EIGHT_TORSION[0]).compress().as_bytes())?;
        // see receiver for discussion of why to multiply by the cofactor (i.e. 8)
        // do we need this? and if, then we can't use *= !!!
        // y *= eight;
        s = s.mul_by_cofactor();
        Ok(ChouOrlandiOTSender {conn: conn, y: y, t: (y * s).mul_by_cofactor()})
    }
}

pub struct ChouOrlandiOTReceiver<T: Read + Write> {
    conn: T,
    s: EdwardsPoint
}


impl <T: Read + Write> ChouOrlandiOTReceiver <T> {
    fn new<R>(mut conn: T, rng: &mut R) -> Result<Self, super::Error> where R:Rng {
        let mut buf: [u8; 32] = [0; 32];
        conn.read_exact(&mut buf);
        let s = CompressedEdwardsY(buf);
        unimplemented!()
    }
}



