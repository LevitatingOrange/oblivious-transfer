use ::errors::*;
use async::base_ot::chou::{ChouOrlandiOTReceiver, ChouOrlandiOTSender};
use common::digest::ArbitraryDigest;
use async::communication::{BinaryReceive, BinarySend};
use rand::{Rng, CryptoRng, RngCore};
use futures::*;

pub struct IKNPExtendedOTReceiver<T, A>
where
    T: BinaryReceive + BinarySend,
    A: ArbitraryDigest + Clone,
{
    conn: T,
    arbitrary_hasher: A,
    initial_pairs: Vec<(Vec<u8>, Vec<u8>)>,
}

/// security parameter: number of bytes to use
impl<T: BinaryReceive + BinarySend, A: ArbitraryDigest + Clone> IKNPExtendedOTReceiver<T, A> {
    pub fn new<S, R>(
        arbitrary_hasher: A,
        mut base_ot_sender: ChouOrlandiOTSender,
        mut rng: R,
        security_param: usize,
    ) -> impl Future<Item = Self, Error = Error>
    where
        R: RngCore + CryptoRng,
    {
        let l = security_param * 8;
        let mut initial_pairs = Vec::with_capacity(l);
        let state = (Some(base_ot_sender), 0);
        let stream = stream::unfold(
            state, |(mut sender, i): (Option<ChouOrlandiOTSender>, usize)| {
                if i < l {
            let mut k0: Vec<u8> = Vec::with_capacity(security_param);
            let mut k1: Vec<u8> = Vec::with_capacity(security_param);
            for _ in 0..security_param {
                k0.push(rng.gen());
                k1.push(rng.gen());
            }
                    initial_pairs.push(k0, k1);
                    sender.unwrap().send(vec![k0.clone(), k1.clone()]).map(|s| (Some(s), i+1))
                } else {
                    None
                }
            }
        ).collect().map(|mut selfs: Vec<Option<ChouOrlandiOTSender>>| {
            Ok(IKNPExtendedOTReceiver {
                arbitrary_hasher: arbitrary_hasher,
                conn: selfs.pop().unwrap().unwrap().conn,
                initial_pairs: initial_pairs,
            })
        });
        stream
    }
}