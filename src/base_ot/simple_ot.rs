//! chou and orlandis 1-out-of-n OT [https://eprint.iacr.org/2015/267.pdf]

use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE, EIGHT_TORSION};
use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};
use curve25519_dalek::scalar::{Scalar};

use futures::prelude::*;
use generic_array::{ArrayLength, GenericArray};
use failure::{Fallible, err_msg};
use crate::crypto::{SymmetricCryptoProvider, Digest};
use crate::util::{read_data, write_data};
use rand::{CryptoRng, RngCore};

async fn receive_point<T>(conn: &mut T) -> Fallible<EdwardsPoint>
where
    T: AsyncRead + AsyncReadExt,
{
    let mut bytes = [0u8; 32];
    await!(conn.read_exact(&mut bytes))?;
    CompressedEdwardsY(bytes)
        .decompress()
        .ok_or_else(|| err_msg("Could not decode point"))
}

async fn send_point<T>(conn: &mut T, p: EdwardsPoint) -> Fallible<()>
where
    T: AsyncWrite + AsyncWriteExt,
{
    let compressed = p.compress();
    await!(conn.write_all(compressed.as_bytes()))?;
    Ok(())
}

pub struct SimpleOTSender<T, D, L, S> where 
T: AsyncRead + AsyncReadExt + AsyncWrite + AsyncWriteExt,
D: Digest<OutputSize = L> + Clone,
L: ArrayLength<u8>,
S: SymmetricCryptoProvider<L> {
    pub conn: T,
    hasher: D,
    crypt: S,
    y: Scalar,
    t64: EdwardsPoint
}

impl<
T: AsyncRead + AsyncReadExt + AsyncWrite + AsyncWriteExt,
D: Digest<OutputSize = L> + Clone,
L: ArrayLength<u8>,
S: SymmetricCryptoProvider<L>
    > SimpleOTSender<T, D, L, S>
{
    pub async fn new<R>(mut conn: T, mut hasher: D, crypt: S, mut rng: R) -> Fallible<Self>
    where
        R: RngCore + CryptoRng,
    {
        let y = Scalar::random(&mut rng);
        let mut s = &y * &ED25519_BASEPOINT_TABLE;

        // we dont send s directly, instead we add a point from the eight torsion subgroup.
        // This enables the receiver to verify that s is in the subgroup of the twisted edwards curve
        // 25519 of Bernstein et al. [TODO: CITE]
        await!(send_point(&mut conn, s + EIGHT_TORSION[1]))?;
        // see ChouOrlandiOTReceiver::new for discussion of why to multiply by the cofactor (i.e. 8)
        s = s.mul_by_cofactor();
        hasher.input(s.compress().as_bytes());
        Ok(SimpleOTSender {
            conn,
            hasher,
            crypt,
            y,
            t64: (y * s).mul_by_cofactor(),
        })
    }

    pub async fn compute_keys(&mut self, n: u64) -> Fallible<Vec<GenericArray<u8, L>>> {
        let mut hasher = self.hasher.clone();
        let r = await!(receive_point(&mut self.conn))?.mul_by_cofactor();
        // seed the hash function with s and r in its compressed form
        hasher.input(r.compress().as_bytes());
        Ok((0..n)
            .map(|j| {
                // hash p=64yR - 64jT, this will reduce to 64xS if c == j, but as x is only known
                // to the receiver (provided the discrete logartihm problem is hard in our curve)
                // the sender does not know c.
                let p = self.y * r - Scalar::from(j) * self.t64;
                let mut hasher = hasher.clone();
                hasher.input(p.compress().as_bytes());
                hasher.result()
            })
            .collect())
    }

    pub async fn send<'a>(&'a mut self, values: &'a[&'a[u8]]) -> Fallible<()> {
        let keys = await!(self.compute_keys(values.len() as u64))?;
        // TODO: make this idiomatic, compute_keys, is copy ok here?
        for (key, value) in keys.into_iter().zip(values) {
            let mut buf: Vec<u8> = value.to_vec();
            buf = await!(self.crypt.encrypt(&key, buf))?;
            await!(write_data(&mut self.conn, &buf))?;
        }
        Ok(())
    }
}

pub struct SimpleOTReceiver<T, R, D, L, S>
where
    T: AsyncRead + AsyncReadExt + AsyncWrite + AsyncWriteExt,
    R: RngCore + CryptoRng,
    D: Digest<OutputSize = L> + Clone,
    L: ArrayLength<u8>,
    S: SymmetricCryptoProvider<L>,
{
    pub conn: T,
    hasher: D,
    crypt: S,
    rng: R,
    s8: EdwardsPoint,
}

impl<
    T: AsyncRead + AsyncReadExt + AsyncWrite + AsyncWriteExt,
    R: RngCore + CryptoRng,
    D: Digest<OutputSize = L> + Clone,
    L: ArrayLength<u8>,
    S: SymmetricCryptoProvider<L>,
    > SimpleOTReceiver<T, R, D, L, S>
{
    pub async fn new(mut conn: T, mut hasher: D, crypt: S, rng: R) -> Fallible<Self> {
        let mut s = await!(receive_point(&mut conn))?;
        // as we've added a point from the eight torsion subgroup to s before sending,
        // by multiplying with the cofactor (i.e. 8, i.e. the order of the eight torsion subgroup)
        // we get [8]s and can be sure that the received value is indeed in the subgroup
        // of our 25519 twisted edwards curve. To avoid a costly division operation (by 8), we
        // operate on 8 and later on 64 times our initial values. [TODO: Cite]
        s = s.mul_by_cofactor();
        hasher.input(s.compress().as_bytes());
        Ok(SimpleOTReceiver {
            conn,
            hasher,
            crypt,
            rng,
            s8: s,
        })
    }

    pub async fn compute_key(&mut self, c: u64) -> Fallible<GenericArray<u8, L>> {
        let mut hasher = self.hasher.clone();
        let x = Scalar::random(&mut self.rng);
        let r = Scalar::from(c) * self.s8 + (&x * &ED25519_BASEPOINT_TABLE).mul_by_cofactor();

        await!(send_point(&mut self.conn, r + EIGHT_TORSION[1]))?;

        // seed the hash function with s and r in it's compressed form
        hasher.input(r.mul_by_cofactor().compress().as_bytes());

        // hash p = 64xS
        let p = (x * Scalar::from(8u64)) * self.s8;
        hasher.input(p.compress().as_bytes());
        Ok(hasher.result())
    }


    pub async fn receive(&mut self, index: usize, n: usize) -> Fallible<Vec<u8>> {
        let key = await!(self.compute_key(index as u64))?;
        let mut buffers: Vec<Vec<u8>> = Default::default();
        for _ in 0..n {
            buffers.push(await!(read_data(&mut self.conn))?);
        }
        let buf = await!(self.crypt.decrypt(&key, buffers.remove(index)))?;
        Ok(buf)
    }
}

// #[cfg(test)]
// mod tests {
// }
