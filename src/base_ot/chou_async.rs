use communication::{BinaryReceive, BinarySend};
use crypto::{SymmetricDecryptor, SymmetricEncryptor};
use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE, EIGHT_TORSION};
use curve25519_dalek::edwards::*;
use curve25519_dalek::scalar::*;
use digest::Digest;
/// chou and orlandis 1-out-of-n OT
/// for all following explanations consider [https://eprint.iacr.org/2015/267.pdf] as source
/// TODO: make this parallel
use errors::*;
use generic_array::{ArrayLength, GenericArray};
use rand::Rng;
use tokio::io::{read_exact, write_all};
use tokio::prelude::*;
use tokio::prelude::future::ok;

fn send_point<T>(conn: T, point: EdwardsPoint) -> impl Future<Item = T, Error = Error>
where
    T: AsyncWrite,
{
    write_all(conn, point.compress().as_bytes().clone())
        .map_err(|e| Error::with_chain(e, "Error while sending point"))
        .map(|(conn, _)| conn)
}

fn receive_point<T>(conn: T) -> impl Future<Item = (EdwardsPoint, T), Error = Error>
where
    T: AsyncRead,
{
    let v: [u8; 32] = Default::default();
    read_exact(conn, v)
        .map_err(move |e| Error::with_chain(e, "Error while receiving point"))
        .and_then(|(conn, buf)| {
            CompressedEdwardsY(buf)
                .decompress()
                .ok_or(ErrorKind::PointError.into())
                .map(|p| (p, conn))
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
    conn: Option<T>,
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
    pub fn new<R>(
        conn: T,
        mut hasher: D,
        encryptor: S,
        rng: &mut R,
    ) -> impl Future<Item = Self, Error = Error>
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
                conn: Some(conn),
                hasher: hasher,
                encryptor: encryptor,
                y: y,
                t64: (y * s).mul_by_cofactor(),
            })
        })
    }

    pub fn compute_keys(
        mut self,
        n: u64,
    ) -> impl Future<Item = (Self, Vec<GenericArray<u8, L>>), Error = Error> {
        receive_point(self.conn.take().unwrap()).and_then(move |(mut r, conn)| {
            self.conn = Some(conn);
            r = r.mul_by_cofactor();
            // seed the hash function with s and r in its compressed form
            self.hasher.input(r.compress().as_bytes());
            let result = (0..n)
                .map(|j| {
                    // hash p=64yR - 64jT, this will reduce to 64xS if c == j, but as x is only known
                    // to the receiver (provided the discrete logartihm problem is hard in our curve)
                    // the sender does not know c.
                    let p = self.y * r - Scalar::from_u64(j) * self.t64;
                    let mut hasher = self.hasher.clone();
                    hasher.input(p.compress().as_bytes());
                    hasher.result()
                })
                .collect();
            Ok((self, result))
        })
    }
}

#[derive(Clone)]
pub struct ChouOrlandiOTReceiver<T, R, D, L, S>
where
    T: AsyncRead + AsyncWrite,
    R: Rng,
    D: Digest<OutputSize = L> + Clone,
    L: ArrayLength<u8>,
    S: SymmetricDecryptor<L>,
{
    conn: Option<T>,
    hasher: D,
    decryptor: S,
    rng: R,
    s8: EdwardsPoint,
}

impl<
        T: AsyncRead + AsyncWrite,
        R: Rng,
        D: Digest<OutputSize = L> + Clone,
        L: ArrayLength<u8>,
        S: SymmetricDecryptor<L>,
    > ChouOrlandiOTReceiver<T, R, D, L, S>
{
    pub fn new(
        conn: T,
        mut hasher: D,
        decryptor: S,
        rng: R,
    ) -> impl Future<Item = Self, Error = Error> {
        receive_point(conn).and_then(move |(mut s, conn)| {
            // as we've added a point from the eight torsion subgroup to s before sending,
            // by multiplying with the cofactor (i.e. 8, i.e. the order of the eight torsion subgroup)
            // we get [8]s and can be sure that the received value is indeed in the subgroup
            // of our 25519 twisted edwards curve. To avoid a costly division operation (by 8), we
            // operate on 8 and later on 64 times our initial values. [TODO: Cite]
            s = s.mul_by_cofactor();
            hasher.input(s.compress().as_bytes());
            Ok(ChouOrlandiOTReceiver {
                conn: Some(conn),
                hasher: hasher,
                decryptor: decryptor,
                rng: rng,
                s8: s,
            })
        })
    }

    pub fn compute_key(
        mut self,
        c: u64,
    ) -> impl Future<Item = (Self, GenericArray<u8, L>), Error = Error> {
        let mut hasher = self.hasher.clone();
        let x = Scalar::random(&mut self.rng);
        let r = Scalar::from_u64(c) * self.s8 + (&x * &ED25519_BASEPOINT_TABLE).mul_by_cofactor();

        send_point(self.conn.take().unwrap(), r + EIGHT_TORSION[1]).and_then(move |conn| {
            self.conn = Some(conn);
            // seed the hash function with s and r in it's compressed form
            hasher.input(r.mul_by_cofactor().compress().as_bytes());

            // hash p = 64xS
            // TODO: is it better to use mul_by_cofactor?
            let p = (x * Scalar::from_u64(8)) * self.s8;
            hasher.input(p.compress().as_bytes());
            Ok((self, hasher.result()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::dummy::DummyCryptoProvider;
    use rand::OsRng;
    use sha3::Sha3_256;
    use tokio;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::prelude::*;
    #[test]
    fn chou_ot_key_exchange() {
        const index: u64 = 3;
        const num: u64 = 10;
        let addr = "127.0.0.1:1236".parse().unwrap();
        let server = TcpListener::bind(&addr)
            .unwrap()
            .incoming().take(1)
            .map_err(|err| eprintln!("Error establishing Connection {:?}", err))
            .and_then(move |socket| {
                let sender = ChouOrlandiOTSender::new(
                    socket,
                    Sha3_256::default(),
                    DummyCryptoProvider::default(),
                    &mut OsRng::new().unwrap(),
                ).and_then(|s| s.compute_keys(num))
                    .map(|(_, result)| result)
                    .map_err(|err| eprintln!("Sender Error: {}", err));
                sender
            }).into_future().map(|(e, _)| e).map_err(|_| eprintln!("Server error"));
        let client = TcpStream::connect(&addr)
            .map_err(move |e| Error::with_chain(e, "Error while trying to connect to sender"))
            .and_then(|s| {
                ChouOrlandiOTReceiver::new(
                    s,
                    Sha3_256::default(),
                    DummyCryptoProvider::default(),
                    OsRng::new().unwrap(),
                )
            })
            .and_then(|r| r.compute_key(index))
            .map(|(_, result)| result)
            .map_err(|err| eprintln!("Receiver Error: {}", err));


        tokio::run(server.join(client).map(|(k, key)| {
            let keys = k.unwrap();
            assert_eq!(num, keys.len() as u64);
            assert_eq!(keys[index as usize], key);
        }));
        // let hashes_sender = server.join().unwrap();
        // let hash_receiver = client.join().unwrap();

        // assert_eq!(hashes_sender[index as usize], hash_receiver)
    }
}
