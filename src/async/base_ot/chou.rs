use async::communication::websockets::*;
use async::crypto::{SymmetricDecryptor, SymmetricEncryptor};
use common::digest::Digest;
use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE, EIGHT_TORSION};
use curve25519_dalek::edwards::*;
use curve25519_dalek::scalar::*;
/// chou and orlandis 1-out-of-n OT
/// for all following explanations consider [https://eprint.iacr.org/2015/267.pdf] as source
/// TODO: make this parallel
use errors::*;
use futures::prelude::*;
use futures::stream;
use generic_array::{ArrayLength, GenericArray};
use rand::Rng;
use std::sync::{Arc, Mutex};

//use stdweb::{__internal_console_unsafe, __js_raw_asm, _js_impl, console, js};

// TODO use traits
fn send_point(
    conn: Arc<Mutex<WasmWebSocket>>,
    point: EdwardsPoint,
) -> impl Future<Item = (), Error = Error> {
    conn.lock()
        .unwrap()
        .write(point.compress().as_bytes().to_vec())
        .map(|_| ())
        .map_err(|e| Error::with_chain(e, "Error while sending point"))
}

fn receive_point(
    conn: Arc<Mutex<WasmWebSocket>>,
) -> impl Future<Item = EdwardsPoint, Error = Error> {
    conn.lock()
        .unwrap()
        .read()
        .map_err(move |e| Error::with_chain(e, "Error while receiving point"))
        .and_then(|(_, buf)| {
            if buf.len() != 32 {
                return Err("Did not receive exactly 32 bytes for point".into());
            }
            // Copy here is inefficient, as we already own buf and do not return it
            CompressedEdwardsY(array_ref![buf, 0, 32].clone())
                .decompress()
                .ok_or(ErrorKind::PointError.into())
        })
}

#[derive(Clone)]
pub struct ChouOrlandiOTSender<D, L, S>
where
    D: Digest<OutputSize = L> + Clone,
    L: ArrayLength<u8>,
    S: SymmetricEncryptor<L>,
{
    conn: Arc<Mutex<WasmWebSocket>>,
    hasher: D,
    encryptor: S,
    y: Scalar,
    t64: EdwardsPoint,
}

impl<D: Digest<OutputSize = L> + Clone, L: ArrayLength<u8>, S: SymmetricEncryptor<L>>
    ChouOrlandiOTSender<D, L, S>
{
    pub fn new<R>(
        conn: Arc<Mutex<WasmWebSocket>>,
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
        send_point(conn.clone(), s + EIGHT_TORSION[1]).and_then(move |_| {
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
        })
    }

    pub fn compute_keys(
        self,
        n: u64,
    ) -> impl Future<Item = (Self, Vec<GenericArray<u8, L>>), Error = Error> {
        receive_point(self.conn.clone()).and_then(move |mut r| {
            r = r.mul_by_cofactor();
            // seed the hash function with r in its compressed form
            let mut hasher = self.hasher.clone();
            hasher.input(r.compress().as_bytes());
            let result = (0..n)
                .map(|j| {
                    // hash p=64yR - 64jT, this will reduce to 64xS if c == j, but as x is only known
                    // to the receiver (provided the discrete logartihm problem is hard in our curve)
                    // the sender does not know c.
                    let p = self.y * r - Scalar::from_u64(j) * self.t64;
                    let mut hasher = hasher.clone();
                    hasher.input(p.compress().as_bytes());
                    hasher.result()
                })
                .collect();
            Ok((self, result))
        })
    }

    // TODO: should the values be owned?
    pub fn send(self, values: Vec<Vec<u8>>) -> impl Future<Item = Self, Error = Error> {
        self.compute_keys(values.len() as u64)
            .map_err(|e| Error::with_chain(e, "Error computing keys"))
            .and_then(move |(s, keys)| {
                let state = (Some(s), keys.into_iter().zip(values).rev().collect());
                let stream = stream::unfold(
                    state,
                    |(mut s, mut kv): (Option<Self>, Vec<(GenericArray<u8, L>, Vec<u8>)>)| {
                        if let Some((key, value)) = kv.pop() {
                            let mut so = s.take().unwrap();
                            let conn = so.conn.clone();
                            let future = so.encryptor.encrypt(&key, value).and_then(move |value| {
                                let lock = conn.lock().unwrap();
                                let (ret, state) = if kv.len() == 0 {
                                    (Some(so), None)
                                } else {
                                    (None, Some(so))
                                };
                                lock.write(value).map(move |_| (ret, (state, kv)))
                            });
                            Some(future)
                        } else {
                            None
                        }
                    },
                );
                stream
                    .collect()
                    .map(|mut selfs: Vec<Option<Self>>| selfs.pop().unwrap().unwrap())
                    .map_err(|e| Error::with_chain(e, "Error sending encrypted data"))
            })
    }
}

#[derive(Clone)]
pub struct ChouOrlandiOTReceiver<R, D, L, S>
where
    R: Rng,
    D: Digest<OutputSize = L> + Clone,
    L: ArrayLength<u8>,
    S: SymmetricDecryptor<L>,
{
    conn: Arc<Mutex<WasmWebSocket>>,
    hasher: D,
    decryptor: S,
    rng: R,
    s8: EdwardsPoint,
}

impl<R: Rng, D: Digest<OutputSize = L> + Clone, L: ArrayLength<u8>, S: SymmetricDecryptor<L>>
    ChouOrlandiOTReceiver<R, D, L, S>
{
    pub fn new(
        conn: Arc<Mutex<WasmWebSocket>>,
        mut hasher: D,
        decryptor: S,
        rng: R,
    ) -> impl Future<Item = Self, Error = Error> {
        receive_point(conn.clone()).and_then(move |mut s| {
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
        })
    }

    pub fn compute_key(
        mut self,
        c: u64,
    ) -> impl Future<Item = (Self, GenericArray<u8, L>), Error = Error> {
        let mut hasher = self.hasher.clone();
        let x = Scalar::random(&mut self.rng);
        let r = Scalar::from_u64(c) * self.s8 + (&x * &ED25519_BASEPOINT_TABLE).mul_by_cofactor();

        send_point(self.conn.clone(), r + EIGHT_TORSION[1]).and_then(move |_| {
            // seed the hash function with s and r in it's compressed form
            hasher.input(r.mul_by_cofactor().compress().as_bytes());
            // hash p = 64xS
            // TODO: is it better to use mul_by_cofactor?
            let p = (x * Scalar::from_u64(8)) * self.s8;
            hasher.input(p.compress().as_bytes());
            Ok((self, hasher.result()))
        })
    }

    // TODO: don't specify size?
    pub fn receive(self, c: usize, n: usize) -> impl Future<Item = (Self, Vec<u8>), Error = Error> {
        self.compute_key(c as u64)
            .map_err(|e| Error::with_chain(e, "Error computing keys"))
            .and_then(move |(mut s, key)| {
                let state = (s.conn.clone(), 0);
                stream::unfold(
                    state,
                    move |(conn, i): (Arc<Mutex<WasmWebSocket>>, usize)| {
                        if i < n {
                            let next_conn = conn.clone();
                            let fut = conn.lock()
                                .unwrap()
                                .read()
                                .map(move |(_, buf)| (buf, (next_conn, i + 1)));
                            Some(fut)
                        } else {
                            None
                        }
                    },
                ).collect()
                    .map_err(|e| Error::with_chain(e, "Error receiving encrypted data"))
                    .and_then(move |mut vals: Vec<Vec<u8>>| {
                        if c < n {
                            Ok(vals.remove(c))
                        } else {
                            Err("index out of bounds".into())
                        }
                    })
                    .and_then(move |buf| s.decryptor.decrypt(&key, buf).map(|v| (s, v)))
            })
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crypto::dummy::DummyCryptoProvider;
//     use crypto::sodium::SodiumCryptoProvider;
//     use rand::OsRng;
//     use rand::thread_rng;
//     use sha3::Sha3_256;
//     use tokio;
//     use tokio::net::{TcpListener, TcpStream};

//     fn create_random_strings(n: usize, l: usize) -> Vec<Vec<u8>> {
//         let mut rng = thread_rng();
//         let mut values = Vec::with_capacity(n);
//         for _ in 0..n {
//             let s: String = rng.gen_ascii_chars().take(l).collect();
//             values.push(s.into_bytes());
//         }
//         values
//     }

//     #[test]
//     fn chou_ot_key_exchange() {
//         let index: u64 = 3;
//         let num: u64 = 10;
//         let addr = "127.0.0.1:1136".parse().unwrap();
//         let server = TcpListener::bind(&addr)
//             .unwrap()
//             .incoming().take(1)
//             .map_err(|err| eprintln!("Error establishing Connection {:?}", err))
//             .and_then(move |socket| {
//                 let sender = ChouOrlandiOTSender::new(
//                     socket,
//                     Sha3_256::default(),
//                     DummyCryptoProvider::default(),
//                     &mut OsRng::new().unwrap(),
//                 ).and_then(move |s| s.compute_keys(num))
//                     .map(|(_, result)| result)
//                     .map_err(|err| eprintln!("Sender Error: {}", err));
//                 sender
//             }).into_future().map(|(e, _)| e).map_err(|_| eprintln!("Server error"));
//         let client = TcpStream::connect(&addr)
//             .map_err(move |e| Error::with_chain(e, "Error while trying to connect to sender"))
//             .and_then(|s| {
//                 ChouOrlandiOTReceiver::new(
//                     s,
//                     Sha3_256::default(),
//                     DummyCryptoProvider::default(),
//                     OsRng::new().unwrap(),
//                 )
//             })
//             .and_then(move |r| r.compute_key(index))
//             .map(|(_, result)| result)
//             .map_err(|err| eprintln!("Receiver Error: {}", err));

//         tokio::run(server.join(client).map(move |(k, key)| {
//             let keys = k.unwrap();
//             assert_eq!(num, keys.len() as u64);
//             assert_eq!(keys[index as usize], key);
//         }));
//     }
//     #[test]
//     fn chou_with_sodium() {

//         let n = 10;
//         let l = 10;
//         let c = thread_rng().gen_range(0, n);

//         let addr = "127.0.0.1:1137".parse().unwrap();
//         let server = TcpListener::bind(&addr)
//             .unwrap()
//             .incoming().take(1)
//             .map_err(|err| eprintln!("Error establishing Connection {:?}", err))
//             .and_then(move |socket| {
//                 let values = create_random_strings(n, l);
//                 let set = values[c].to_owned();
//                 let sender = ChouOrlandiOTSender::new(
//                     socket,
//                     Sha3_256::default(),
//                     SodiumCryptoProvider::default(),
//                     &mut OsRng::new().unwrap(),
//                 ).and_then(move |s| s.send(values))
//                     .map_err(|err| eprintln!("Sender Error: {}", err))
//                     .map(|_| set);
//                 sender
//             }).into_future().map(|(e, _)| e)
//             .map_err(|_| eprintln!("Server error"));
//         let client = TcpStream::connect(&addr)
//             .map_err(move |e| Error::with_chain(e, "Error while trying to connect to sender"))
//             .and_then(|s| {
//                 ChouOrlandiOTReceiver::new(
//                     s,
//                     Sha3_256::default(),
//                     SodiumCryptoProvider::default(),
//                     OsRng::new().unwrap(),
//                 )
//             })
//             .and_then(move |r| r.receive(c, n))
//             .map_err(|err| eprintln!("Receiver Error: {}", err));

//         tokio::run(server.join(client).map(move |(set, actual)| {
//             assert_eq!(set.unwrap(), actual);
//             // let keys = k.unwrap();
//             // assert_eq!(num, keys.len() as u64);
//             // assert_eq!(keys[index as usize], key);
//         }));
//     }

// }
