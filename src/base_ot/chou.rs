/// chou and orlandis 1-out-of-n OT
/// for all following explanations consider [https://eprint.iacr.org/2015/267.pdf] as source

use std::io::prelude::*;
use rand::Rng;
use curve25519_dalek::edwards::*;
use curve25519_dalek::scalar::*;
use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE, EIGHT_TORSION};
use std::vec::Vec;
use std::iter::Iterator;
use digest::Digest;
use generic_array::{ArrayLength, GenericArray};
use crypto::{SymmetricDecryptor, SymmetricEncryptor};

pub struct ChouOrlandiOTSender<T, D, E, S>
where
    T: Read + Write,
    D: Digest<OutputSize = E> + Clone,
    E: ArrayLength<u8>,
    S: SymmetricEncryptor<E>,
{
    conn: T,
    hasher: D,
    encryptor: S,
    y: Scalar,
    t64: EdwardsPoint,
}

fn receive_point<T>(conn: &mut T) -> Result<EdwardsPoint, super::Error>
where
    T: Read,
{
    let mut buf: [u8; 32] = Default::default();
    conn.read_exact(&mut buf)?;
    CompressedEdwardsY(buf)
        .decompress()
        .ok_or(super::Error::PointError)
}

// TODO: parallelize the protocol

impl<
    T: Read + Write,
    D: Digest<OutputSize = E> + Clone,
    E: ArrayLength<u8>,
    S: SymmetricEncryptor<E>,
> ChouOrlandiOTSender<T, D, E, S>
{
    pub fn new<R>(
        mut conn: T,
        mut hasher: D,
        encryptor: S,
        rng: &mut R,
    ) -> Result<Self, super::Error>
    where
        R: Rng,
    {
        let y = Scalar::random(rng);
        let mut s = &y * &ED25519_BASEPOINT_TABLE;

        // we dont send s directly, instead we add a point from the eight torsion subgroup.
        // This enables the receiver to verify that s is in the subgroup of the twisted edwards curve
        // 25519 of Bernstein et al. [TODO: CITE]
        conn.write_all((s + EIGHT_TORSION[1]).compress().as_bytes())?;
        // see ChouOrlandiOTReceiver::new for discussion of why to multiply by the cofactor (i.e. 8)
        s = s.mul_by_cofactor();
        hasher.input(s.compress().as_bytes());
        Ok(ChouOrlandiOTSender {
            conn: conn,
            hasher: hasher,
            encryptor: encryptor,
            y: y,
            t64: (y * s).mul_by_cofactor(),
        })
    }

    fn compute_keys(&mut self, n: u64) -> Result<Vec<GenericArray<u8, E>>, super::Error> {
        let mut hasher = self.hasher.clone();
        let r = receive_point(&mut self.conn)?.mul_by_cofactor();
        // seed the hash function with s and r in its compressed form
        hasher.input(r.compress().as_bytes());
        Ok((0..n)
            .map(|j| {
                // hash p=64yR - 64jT, this will reduce to 64xS if c == j, but as x is only known
                // to the receiver (provided the discrete logartihm problem is hard in our curve)
                // the sender does not know c.
                let p = self.y * r - Scalar::from_u64(j) * self.t64;
                let mut hasher = hasher.clone();
                hasher.input(p.compress().as_bytes());
                hasher.result()
            })
            .collect())
    }
}

impl<
    T: Read + Write,
    D: Digest<OutputSize = E> + Clone,
    E: ArrayLength<u8>,
    S: SymmetricEncryptor<E>,
> super::BaseOTSender for ChouOrlandiOTSender<T, D, E, S>
{
    fn send(&mut self, values: Vec<&[u8]>) -> Result<(), super::Error> {
        let keys = self.compute_keys(values.len() as u64)?;
        // TODO: make this idiomatic, compute_keys, is copy ok here?
        for (key, value) in keys.into_iter().zip(values) {
            let mut buf = value.to_owned();
            self.encryptor.encrypt(key, &mut buf);
            self.conn.write_all(&mut buf)?;
            self.conn.flush()?;
        }
        Ok(())
    }
}

pub struct ChouOrlandiOTReceiver<T, R, D, E, S>
where
    T: Read + Write,
    R: Rng,
    D: Digest<OutputSize = E> + Clone,
    E: ArrayLength<u8>,
    S: SymmetricDecryptor<E>,
{
    conn: T,
    hasher: D,
    decryptor: S,
    rng: R,
    s8: EdwardsPoint,
}

impl<
    T: Read + Write,
    R: Rng,
    D: Digest<OutputSize = E> + Clone,
    E: ArrayLength<u8>,
    S: SymmetricDecryptor<E>,
> ChouOrlandiOTReceiver<T, R, D, E, S>
{
    pub fn new(mut conn: T, mut hasher: D, decryptor: S, rng: R) -> Result<Self, super::Error> {
        let mut s = receive_point(&mut conn)?;

        // as we've added a point from the eight torsion subgroup to s before sending,
        // by multiplying with the cofactor (i.e. 8, i.e. the order of the eight torsion subgroup)
        // we get [8]s and can be sure that the received value is indeed in the subgroup
        // of our 25519 twisted edwards curve. To avoid a costly division operation (by 8), we
        // operate on 8 and later on 64 times our initial values. [TODO: Cite]
        s = s.mul_by_cofactor();
        hasher.input(s.compress().as_bytes());
        Ok(ChouOrlandiOTReceiver {
            conn: conn,
            hasher: hasher,
            decryptor: decryptor,
            rng: rng,
            s8: s,
        })
    }

    fn compute_key(&mut self, c: u64) -> Result<GenericArray<u8, E>, super::Error> {
        let mut hasher = self.hasher.clone();
        let x = Scalar::random(&mut self.rng);
        let r = Scalar::from_u64(c) * self.s8 + (&x * &ED25519_BASEPOINT_TABLE).mul_by_cofactor();
        self.conn
            .write_all((r + EIGHT_TORSION[1]).compress().as_bytes())?;

        // seed the hash function with s and r in it's compressed form
        hasher.input(r.mul_by_cofactor().compress().as_bytes());

        // hash p = 64xS
        // TODO: is it better to use mul_by_cofactor?
        let p = (x * Scalar::from_u64(8)) * self.s8;
        hasher.input(p.compress().as_bytes());
        Ok(hasher.result())
    }
}

impl<
    T: Read + Write,
    R: Rng,
    D: Digest<OutputSize = E> + Clone,
    E: ArrayLength<u8>,
    S: SymmetricDecryptor<E>,
> super::BaseOTReceiver for ChouOrlandiOTReceiver<T, R, D, E, S>
{
    fn receive(&mut self, index: u64, n: usize, l: usize) -> Result<Vec<u8>, super::Error> {
        let key = self.compute_key(index)?;
        println!("key: {:?}", key);
        // TODO make this idiomatic
        let mut buf: Vec<u8> = Vec::with_capacity(l);
        buf.resize(l, 0);
        let mut _buf: Vec<u8> = Vec::with_capacity(l);
        _buf.resize(l, 0);
        for i in 0..n {
            if i == index as usize {
                self.conn.read_exact(&mut buf)?;
            } else {
                self.conn.read_exact(&mut _buf)?;
            }
        }
        println!("buf: {:?}", buf);
        self.decryptor.decrypt(key, &mut buf);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use rand::OsRng;
    use super::*;
    use communication::corrupted::CorruptedChannel;
    use std::net::TcpListener;
    use std::net::TcpStream;
    use std::thread;
    use sha3::Sha3_256;
    use crypto::DummySymmetric;

    #[test]
    fn chou_ot_key_exchange() {
        let index = 3;
        let server = thread::spawn(move || {
            let mut ot = ChouOrlandiOTSender::new(
                TcpListener::bind("127.0.0.1:1236")
                    .unwrap()
                    .accept()
                    .unwrap()
                    .0,
                Sha3_256::default(),
                DummySymmetric::default(),
                &mut OsRng::new().unwrap(),
            ).unwrap();
            ot.compute_keys(10).unwrap()
        });
        let client = thread::spawn(move || {
            let mut ot = ChouOrlandiOTReceiver::new(
                TcpStream::connect("127.0.0.1:1236").unwrap(),
                Sha3_256::default(),
                DummySymmetric::default(),
                OsRng::new().unwrap(),
            ).unwrap();
            ot.compute_key(index).unwrap()
        });
        let hashes_sender = server.join().unwrap();
        let hash_receiver = client.join().unwrap();

        assert_eq!(hashes_sender[index as usize], hash_receiver)
    }

    #[test]
    fn chou_ot_key_exchange_multiple() {
        static INDICES: [u64; 5] = [5, 0, 9, 3, 7];

        let server = thread::spawn(move || {
            let mut ot = ChouOrlandiOTSender::new(
                TcpListener::bind("127.0.0.1:1237")
                    .unwrap()
                    .accept()
                    .unwrap()
                    .0,
                Sha3_256::default(),
                DummySymmetric::default(),
                &mut OsRng::new().unwrap(),
            ).unwrap();
            INDICES
                .iter()
                .map(move |i| ot.compute_keys(10).unwrap()[*i as usize])
                .collect()
        });

        let client = thread::spawn(move || {
            let mut ot = ChouOrlandiOTReceiver::new(
                TcpStream::connect("127.0.0.1:1237").unwrap(),
                Sha3_256::default(),
                DummySymmetric::default(),
                OsRng::new().unwrap(),
            ).unwrap();
            INDICES
                .iter()
                .map(move |i| ot.compute_key(*i).unwrap())
                .collect()
        });

        let hashes_sender: Vec<_> = server.join().unwrap();
        let hashes_receiver: Vec<_> = client.join().unwrap();

        for (send_hash, recv_hash) in hashes_sender.iter().zip(hashes_receiver.iter()) {
            assert_eq!(send_hash, recv_hash);
        }
    }

    #[test]
    fn chou_ot_key_exchange_c0() {
        // given c == 0 and a poor implementation an attacker can infer that c is 0 given the transmitted R
        let server = thread::spawn(move || {
            let mut ot = ChouOrlandiOTSender::new(
                TcpListener::bind("127.0.0.1:1238")
                    .unwrap()
                    .accept()
                    .unwrap()
                    .0,
                Sha3_256::default(),
                DummySymmetric::default(),
                &mut OsRng::new().unwrap(),
            ).unwrap();
            ot.compute_keys(10).unwrap()
        });

        // if the transmitted R is wrongly calculated (i.e. c*t + R, where t is an eight torsion point,
        // see ChouOrlandiOTReceiver::new for why we add this eight torsion point), then the point is torsion free
        // if c = 0 and an attacker can infer that c is indeed 0

        fn eavesdrop(_: &mut (), buf: &[u8]) {
            let mut new_buf: [u8; 32] = Default::default();
            new_buf.copy_from_slice(buf);
            assert!(!CompressedEdwardsY(new_buf)
                .decompress()
                .unwrap()
                .is_torsion_free())
        }

        let client = thread::spawn(move || {
            let corrupted_channel = CorruptedChannel::new_eavesdrop(
                TcpStream::connect("127.0.0.1:1238").unwrap(),
                (),
                eavesdrop,
            );
            let mut ot = ChouOrlandiOTReceiver::new(
                corrupted_channel,
                Sha3_256::default(),
                DummySymmetric::default(),
                OsRng::new().unwrap(),
            ).unwrap();
            ot.compute_key(0).unwrap()
        });
        let hashes_sender = server.join().unwrap();
        let hash_receiver = client.join().unwrap();

        assert_eq!(hashes_sender[0], hash_receiver)
    }

}
