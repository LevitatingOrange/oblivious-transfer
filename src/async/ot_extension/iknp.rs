use async::base_ot::{BaseOTReceiver, BaseOTSender};
use async::communication::{BinaryReceive, BinarySend, GetConn};
use common::digest::ArbitraryDigest;
use errors::*;
use futures::*;
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
impl<'a, T: 'a + BinaryReceive + BinarySend, A: 'a + ArbitraryDigest + Clone> IKNPExtendedOTReceiver<T, A> {
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
                            (((k0, k1),Some(s)), (None, i + 1))
                        } else {
                            (((k0, k1), None), (Some(s), i + 1))
                        }
                    });
                Some(future)
            } else {
                None
            }
        }).collect()
            .map(|vals: Vec<((Vec<u8>, Vec<u8>),Option<S>)>| {
                let (initial_pairs, mut selfs): (Vec<(Vec<u8>, Vec<u8>)>, Vec<Option<S>>) = vals.into_iter().unzip();
                IKNPExtendedOTReceiver {
                    arbitrary_hasher: arbitrary_hasher,
                    conn: selfs.pop().unwrap().unwrap().get_conn(),
                    initial_pairs: initial_pairs,
                }
            });
        Box::new(stream)
    }
}