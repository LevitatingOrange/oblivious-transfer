use super::{ExtendedOTReceiver, ExtendedOTSender};
use async::base_ot::{BaseOTReceiver, BaseOTSender};
use async::communication::{BinaryReceive, BinarySend, GetConn};
use bit_vec::BitVec;
use common::digest::ArbitraryDigest;
use common::util::{bv_truncate, trunc_hash};
use errors::*;
use futures::future;
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
    ) -> Box<Future<Item = (Vec<Vec<u8>>), Error = Error> + 'a> {
        let output_size = choice_bits.len();
        let l = self.initial_pairs.len();
        let t_mat: Vec<(BitVec, BitVec)> = self
            .initial_pairs
            .iter()
            .map(|(k0, k1)| (trunc_hash(self.arbitrary_hasher.clone(), output_size, k0), trunc_hash(self.arbitrary_hasher.clone(), output_size, k1)))
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
            .collect().and_then(enclose! { (conn) move |t_mat: Vec<BitVec>| {
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
            }}).map(|r: Vec<Vec<u8>>| (r));
            Box::new(fut)
    }
}
