use super::{ExtendedOTReceiver, ExtendedOTSender};
use common::digest::Digest;
use errors::*;
use generic_array::{ArrayLength, GenericArray};
use rand::Rng;
use sync::base_ot::BaseOTReceiver;
use sync::base_ot::BaseOTSender;
use sync::communication::{BinaryReceive, BinarySend};
use sync::crypto::{SymmetricDecryptor, SymmetricEncryptor};

pub struct AsharovExtendedOTReceiver<T>
where
    T: BinaryReceive + BinarySend,
{
    conn: T,
    initial_pairs: Vec<(Vec<u8>, Vec<u8>)>,
}

pub struct AsharovExtendedOTSender<T>
where
    T: BinaryReceive + BinarySend,
{
    conn: T,
    initial: Vec<Vec<u8>>,
}

/// security parameter: number of bytes to use
impl<T: BinaryReceive + BinarySend> AsharovExtendedOTReceiver<T> {
    pub fn new<S, R>(
        conn: T,
        mut base_ot_sender: S,
        mut rng: R,
        security_param: usize,
    ) -> Result<Self>
    where
        S: BaseOTSender,
        R: Rng,
    {
        let l = security_param * 8;
        let mut initial_pairs = Vec::with_capacity(l);
        for i in 0..l {
            let mut k0: Vec<u8> = Vec::with_capacity(security_param);
            let mut k1: Vec<u8> = Vec::with_capacity(security_param);
            for i in 0..security_param {
                k0[i] = rng.gen();
                k1[i] = rng.gen();
            }
            base_ot_sender.send(vec![&k0, &k1])?;
            initial_pairs[i] = (k0, k1);
        }
        Ok(AsharovExtendedOTReceiver {
            conn: conn,
            initial_pairs: initial_pairs,
        })
    }
}

/// security parameter: number of bytes to use
impl<T: BinaryReceive + BinarySend> AsharovExtendedOTSender<T> {
    pub fn new<S, R>(
        conn: T,
        mut base_ot_receiver: S,
        mut rng: R,
        security_param: usize,
    ) -> Result<Self>
    where
        S: BaseOTReceiver,
        R: Rng,
    {
        let l = security_param * 8;
        let mut initial = Vec::with_capacity(l);
        for i in 0..l {
            let mut choice: bool = rng.gen();
            initial[i] = base_ot_receiver.receive(choice as usize, 2)?;
        }
        Ok(AsharovExtendedOTSender {
            conn: conn,
            initial: initial,
        })
    }
}
