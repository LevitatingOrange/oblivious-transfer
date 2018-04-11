/// chou and orlandis 1-out-of-n OT
use std::io::prelude::*;
use rand::{OsRng, Rng};
use curve25519_dalek::edwards::*;
use curve25519_dalek::scalar::*;


pub struct ChouOrlandiOT<T: Read + Write, R: Rng> {
    conn: T,
    s: EdwardsPoint,
    t: EdwardsPoint,
    rng: R,
}

impl <T: Read + Write, R: Rng> ChouOrlandiOT <T, R> {
    fn new(conn: T, rng: R) -> Self {
        unimplemented!()
    }
}