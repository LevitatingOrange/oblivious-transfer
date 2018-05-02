/// chou and orlandis 1-out-of-n OT
/// for all following explanations consider [https://eprint.iacr.org/2015/267.pdf] as source
use errors::*;
use rand::Rng;
use curve25519_dalek::edwards::*;
use curve25519_dalek::scalar::*;
use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE, EIGHT_TORSION};
use std::vec::Vec;
use std::iter::Iterator;
use digest::Digest;
use generic_array::{ArrayLength, GenericArray};
use crypto::{SymmetricDecryptor, SymmetricEncryptor};
use communication::{BinaryReceive, BinarySend};
use tokio::prelude::*;
use tokio::io::{read_exact, write_all};
use std::rc::Rc;
use std::cell::Cell;

fn send_point<T>(conn: T, point: EdwardsPoint) -> impl Future<Item = T, Error = Error> where T: AsyncWrite {
    write_all(conn, point.compress().as_bytes().clone()).map_err(|e| Error::with_chain(e, "Error while sending point")).map(|(conn, _)| conn)
}

fn receive_point<T>(conn: T) -> impl Future<Item = EdwardsPoint, Error = Error> where T: AsyncRead {
    let v: [u8; 32] = Default::default();
    read_exact(conn, v).map_err(move |e| Error::with_chain(e, "Error while receiving point")).and_then(|(_, buf)| {
        CompressedEdwardsY(buf).decompress().ok_or(ErrorKind::PointError.into())
    })
}



#[derive(Clone)]
pub struct ChouOrlandiOTSender<T, D, L, S>
where
    T: AsyncWrite + AsyncRead,
    D: Digest<OutputSize = L> + Clone,
    L: ArrayLength<u8>,
    S: SymmetricEncryptor<L>,
{
    conn: Rc<Cell<Option<T>>>,
    hasher: D,
    encryptor: S,
    y: Scalar,
    t64: EdwardsPoint,
}

impl<
    T: AsyncWrite + AsyncRead,
    D: Digest<OutputSize = L> + Clone,
    L: ArrayLength<u8>,
    S: SymmetricEncryptor<L>,
> ChouOrlandiOTSender<T, D, L, S>
{
    pub fn new<R>(conn: T, mut hasher: D, encryptor: S, rng: &mut R) -> impl Future<Item = Self, Error = Error>
    where
        R: Rng,
    {
        let y = Scalar::random(rng);
        let mut s = &y * &ED25519_BASEPOINT_TABLE;

        // we dont send s directly, instead we add a point from the eight torsion subgroup.
        // This enables the receiver to verify that s is in the subgroup of the twisted edwards curve
        // 25519 of Bernstein et al. [TODO: CITE]
        send_point(conn, s + EIGHT_TORSION[1]).and_then(move |conn| {
            // see ChouOrlandiOTReceiver::new for discussion of why to multiply by the cofactor (i.e. 8)
            s = s.mul_by_cofactor();
            hasher.input(s.compress().as_bytes());
            Ok(ChouOrlandiOTSender {
                conn: Rc::new(Cell::new(Some(conn))),
                hasher: hasher,
                encryptor: encryptor,
                y: y,
                t64: (y * s).mul_by_cofactor(),
            })
        })
    }

    fn compute_keys(mut self, n: u64) -> impl Future<Item = Vec<GenericArray<u8, L>>, Error = Error> {
        // TODO: this take is very insecure as calling compute_keys before it finished will crash it
        receive_point(self.conn.take().unwrap()).and_then(move |mut r| { 
            r = r.mul_by_cofactor();
            // seed the hash function with s and r in its compressed form
            self.hasher.input(r.compress().as_bytes());
            Ok((0..n).map(|j| {
                    // hash p=64yR - 64jT, this will reduce to 64xS if c == j, but as x is only known
                    // to the receiver (provided the discrete logartihm problem is hard in our curve)
                    // the sender does not know c.
                    let p = self.y * r - Scalar::from_u64(j) * self.t64;
                    let mut hasher = self.hasher.clone();
                    hasher.input(p.compress().as_bytes());
                    hasher.result()
            }).collect())
        })
    }
}