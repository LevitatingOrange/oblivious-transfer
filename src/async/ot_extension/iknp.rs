use super::{ExtendedOTReceiver, ExtendedOTSender};
use async::base_ot::{BaseOTReceiver, BaseOTSender};
use async::communication::{BinaryReceive, BinarySend, GetConn};
use bit_vec::BitVec;
use common::digest::ArbitraryDigest;
use common::util::{bv_truncate, trunc_hash};
use errors::*;
use futures::prelude::*;
use futures::stream;
use rand::{CryptoRng, Rng, RngCore};
use std::sync::{Arc, Mutex};

pub struct IKNPExtendedOTReceiver<T, A>
where
    T: BinaryReceive + BinarySend,
    A: ArbitraryDigest + Clone,
{
    conn: Arc<Mutex<T>>,
    arbitrary_hasher: A,
    initial_pairs: Vec<(Vec<u8>, Vec<u8>)>,
}

/// security parameter: number of bytes to use
impl<'a, T: 'a + BinaryReceive + BinarySend, A: 'a + ArbitraryDigest + Clone>
    IKNPExtendedOTReceiver<T, A>
{
    pub fn new<S, R>(
        arbitrary_hasher: A,
        base_ot_sender: S,
        mut rng: R,
        security_param: usize,
    ) -> Box<Future<Item = Self, Error = Error> + 'a>
    where
        S: 'a + BaseOTSender<'a> + GetConn<T>,
        R: 'a + RngCore + CryptoRng,
    {
        let l = security_param * 8;
        let state = (Some(base_ot_sender), 0);
        let stream = stream::unfold(state, move |(sender, i): (Option<S>, usize)| {
            if i < l {
                let mut k0: Vec<u8> = Vec::with_capacity(security_param);
                let mut k1: Vec<u8> = Vec::with_capacity(security_param);
                for _ in 0..security_param {
                    k0.push(rng.gen());
                    k1.push(rng.gen());
                }
                let future = sender
                    .unwrap()
                    .send(vec![k0.clone(), k1.clone()])
                    .map(move |s| {
                        if i == l - 1 {
                            (((k0, k1), Some(s)), (None, i + 1))
                        } else {
                            (((k0, k1), None), (Some(s), i + 1))
                        }
                    });
                Some(future)
            } else {
                None
            }
        }).collect()
            .map(|vals: Vec<((Vec<u8>, Vec<u8>), Option<S>)>| {
                let (initial_pairs, mut selfs): (
                    Vec<(Vec<u8>, Vec<u8>)>,
                    Vec<Option<S>>,
                ) = vals.into_iter().unzip();
                IKNPExtendedOTReceiver {
                    arbitrary_hasher: arbitrary_hasher,
                    conn: selfs.pop().unwrap().unwrap().get_conn(),
                    initial_pairs: initial_pairs,
                }
            });
        Box::new(stream)
    }
}

impl<'a, T: 'a + BinaryReceive + BinarySend, A: 'a + ArbitraryDigest + Clone> ExtendedOTReceiver<'a>
    for IKNPExtendedOTReceiver<T, A>
{
    fn receive(
        self,
        choice_bits: BitVec,
    ) -> Box<Future<Item = (Vec<Vec<u8>>, Self), Error = Error> + 'a> {
        let output_size = choice_bits.len();
        let l = self.initial_pairs.len();
        let t_mat: Vec<(BitVec, BitVec)> = self
            .initial_pairs
            .iter()
            .map(|(k0, k1)| {
                (
                    trunc_hash(self.arbitrary_hasher.clone(), output_size, k0),
                    trunc_hash(self.arbitrary_hasher.clone(), output_size, k1),
                )
            })
            .collect();

        let choice_bits = Arc::new(choice_bits);

        // because the enclose macro does not expect self.*, maybe fix this in the macro
        let conn = self.conn.clone();
        let hasher = self.arbitrary_hasher.clone();
        let fut = stream::iter_ok(t_mat)
            .and_then(enclose!{ (conn, choice_bits) move |(t, k1)| {
                assert_eq!(t.len(), output_size, "internal error, lengths don't match.");
                assert_eq!(t.len(), k1.len(), "internal error, lengths don't match.");
                assert_eq!(
                    t.len(),
                    choice_bits.len(),
                    "internal error, lengths don't match."
                );
                let u: BitVec = izip!(t.iter(), k1, choice_bits.iter())
                    .map(|(t, k, r)| t ^ k ^ r)
                    .collect();
                let conn = conn.clone();
                let lock = conn.lock().unwrap();
                lock.send(u.to_bytes()).map(|_| {
                    t
                })
            }})
            .collect()
            .and_then(enclose! { (conn) move |t_mat: Vec<BitVec>| {
                stream::iter_ok(0..output_size).and_then(move |i| {
                    let t_mat = t_mat.clone();
                    let lock = conn.lock().unwrap();
                    let mut hasher = hasher.clone();

                    lock.receive().and_then(enclose! { (choice_bits) move |(conn, y0)| {
                        conn.lock().unwrap().receive().map(move |(_, y1)| {
                            let ys = [y0, y1];
                            assert_eq!(
                                ys[0].len(),
                                ys[1].len(),
                                "String pairs do not have same size"
                            );
                            let mut bt = BitVec::with_capacity(l);
                            for j in 0..l {
                                bt.push(t_mat[j][i.clone()]);
                            }
                            hasher.input(&(i as u64).to_bytes());
                            hasher.input(&bt.to_bytes());
                            let ht = hasher.result(ys[0].len());
                            let r: Vec<u8> = ys[choice_bits[i.clone()] as usize]
                                .iter()
                                .zip(ht)
                                .map(|(ht, y)| y ^ ht)
                                .collect();
                            r
                        })
                    }})
                }).collect()
            }})
            .map(|r: Vec<Vec<u8>>| (r, self));
        Box::new(fut)
    }
}

pub struct IKNPExtendedOTSender<T, A>
where
    T: BinaryReceive + BinarySend,
    A: ArbitraryDigest + Clone,
{
    conn: Arc<Mutex<T>>,
    arbitrary_hasher: A,
    initial: Vec<Vec<u8>>,
    random_choices: BitVec,
}

/// security parameter: number of bytes to use
impl<'a, T: 'a + BinaryReceive + BinarySend, A: 'a + ArbitraryDigest + Clone>
    IKNPExtendedOTSender<T, A>
{
    pub fn new<S, R>(
        arbitrary_hasher: A,
        base_ot_receiver: S,
        mut rng: R,
        security_param: usize,
        stat_security_param: usize,
    ) -> Box<Future<Item = Self, Error = Error> + 'a>
    where
        S: 'a + BaseOTReceiver<'a> + GetConn<T>,
        R: 'a + RngCore + CryptoRng,
    {
        // To simplify this protocol both security parameters are specified
        // in bytes and as such have to be multiplied by 8 for certain parts of the protocol.
        let l = (security_param * 8) + (stat_security_param * 8);
        // we generate random choices (0 or 1) and use them to receive
        // `l` seeds (of size `security_param`) from the receiver with the base-OT primitive.
        let state = (Some(base_ot_receiver), 0);
        // let mut random_choices = BitVec::with_capacity(security_param);
        // let mut initial = Vec::with_capacity(security_param);
        let stream = stream::unfold(state, move |(sender, i): (Option<S>, usize)| {
            if i < l {
                let choice: bool = rng.gen();
                let future = sender
                    .unwrap()
                    .receive(choice as usize, 2)
                    .map(move |(val, s)| {
                        if i == l - 1 {
                            (((choice, val), Some(s)), (None, i + 1))
                        } else {
                            (((choice, val), None), (Some(s), i + 1))
                        }
                    });
                Some(future)
            } else {
                None
            }
        }).collect()
            .map(|vals: Vec<((bool, Vec<u8>), Option<S>)>| {
                let (pairs, mut selfs): (Vec<(bool, Vec<u8>)>, Vec<Option<S>>) =
                    vals.into_iter().unzip();
                let (choices, initial) = pairs.into_iter().unzip();

                IKNPExtendedOTSender {
                    arbitrary_hasher: arbitrary_hasher,
                    conn: selfs.pop().unwrap().unwrap().get_conn(),
                    random_choices: choices,
                    initial: initial,
                }
            });
        Box::new(stream)
    }
}

impl<'a, T: 'a + BinaryReceive + BinarySend, A: 'a + ArbitraryDigest + Clone> ExtendedOTSender<'a>
    for IKNPExtendedOTSender<T, A>
{
    fn send(
        self,
        values: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Box<Future<Item = Self, Error = Error> + 'a> {
        let output_size = values.len();
        let l = self.initial.len();
        let security_parameter = self.initial.len();

        // TODO: find better way. This clone is bad as it copies the vectors
        let random_choices = Arc::new(self.random_choices.clone());
        let initial = Arc::new(self.initial.clone());

        let conn = self.conn.clone();
        let arbitrary_hasher = self.arbitrary_hasher.clone();
        let stream = stream::iter_ok(0..security_parameter)
            .and_then(enclose! { (conn) move |_| {
                let lock = conn.lock().unwrap();
                lock.receive().map(move |(_, s)| bv_truncate(&s, output_size))
            }})
            .collect()
            .and_then(enclose!{ (conn, arbitrary_hasher, random_choices) move |us: Vec<BitVec>| {
                assert_eq!(
                    us.len(),
                    initial.len(),
                    "internal error, lengths don't match."
                );
                assert_eq!(
                    us.len(),
                    random_choices.len(),
                    "internal error, lengths don't match."
                );
                let q_mat: Vec<BitVec> = izip!(initial.iter(), &us, random_choices.iter())
                    .map(|(k, u, s)| {
                        let gk = trunc_hash(arbitrary_hasher.clone(), output_size, k);
                        u.iter()
                            .zip(gk)
                            .map(|(u, k)| (((s as u8) * (u as u8)) ^ (k as u8)) == 1)
                            .collect()
                    })
                    .collect();
                let fut = stream::iter_ok(0..security_parameter)
                    .and_then(enclose!{ (conn, arbitrary_hasher, random_choices) move |i| {
                        let lock = conn.lock().unwrap();
                        let n = values[i].0.len();
                        assert_eq!(n, values[i].1.len(), "String pairs do not have same size");
                        let mut qt = BitVec::with_capacity(l);
                        for j in 0..l {
                            qt.push(q_mat[j][i]);
                        }
                        let mut hasher = arbitrary_hasher.clone();
                        hasher.input(&(i as u64).to_bytes());
                        let mut hasher2 = hasher.clone();
                        // TODO make this nicer
                        hasher.input(&qt.to_bytes());
                        let hq = hasher.result(n);
                        let y0: Vec<u8> = values[i].0.iter().zip(hq).map(|(x, q)| x ^ q).collect();
                        let q2: Vec<u8> = qt
                            .to_bytes()
                            .iter()
                            .zip(random_choices.to_bytes())
                            .map(|(q, s)| q ^ s)
                            .collect();
                        hasher2.input(&q2);
                        let shq = hasher2.result(n);
                        let y1: Vec<u8> = values[i].1.iter().zip(shq).map(|(x, q)| x ^ q).collect();
                        lock.send(y0).and_then(|s| {
                            let lock = s.lock().unwrap();
                            lock.send(y1)
                        })
                    }})
                    .collect()
                    .map(move |_: Vec<Arc<Mutex<T>>>| self);
                fut
            }});
        Box::new(stream)
    }
}
