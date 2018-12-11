use crate::crypto::*;
use crate::base_ot::simple_ot::*;
use futures::prelude::*;
use failure::Fallible;
use crate::util::*;

use rand::prelude::*;
use generic_array::{ArrayLength};
use bit_vec::BitVec;
use itertools::izip;


pub struct IKNPExtendedOTReceiver<T, A>
where
    T: AsyncRead + AsyncWrite,
    A: ArbitraryDigest + Clone,
{
    pub conn: T,
    arbitrary_hasher: A,
    initial_pairs: Vec<(Vec<u8>, Vec<u8>)>,
}

impl<T: AsyncRead + AsyncWrite, A: Digest<OutputSize = L> + ArbitraryDigest + Clone, L: ArrayLength<u8>> IKNPExtendedOTReceiver<T, A> {
    pub async fn new<S, R>(
        conn: T,
        hasher: A,
        crypt: S,
        mut rng: R,
        security_param: usize,
    ) -> Fallible<Self>
    where
        S: SymmetricCryptoProvider<L> + Clone + Copy,
        R: RngCore + CryptoRng
    {
        let l = security_param * 8;
        let mut initial_pairs = Vec::with_capacity(l);
        for _ in 0..l {
            let mut k0: Vec<u8> = Vec::with_capacity(security_param);
            let mut k1: Vec<u8> = Vec::with_capacity(security_param);
            for _ in 0..security_param {
                k0.push(rng.gen());
                k1.push(rng.gen());
            }
            initial_pairs.push((k0, k1));
        }
        let mut base_ot_sender = await!(SimpleOTSender::new(conn, hasher.clone(), crypt, rng))?;

        for (k0, k1) in &initial_pairs {
            let sot_in = vec![&k0[..], &k1[..]];
            await!(base_ot_sender.send(&sot_in[..]))?;
        }
        Ok(IKNPExtendedOTReceiver {
            arbitrary_hasher: hasher,
            conn: base_ot_sender.conn,
            initial_pairs,
        })
    }

    pub async fn receive(&mut self, choice_bits: BitVec) -> Fallible<Vec<Vec<u8>>> {
        let output_size = choice_bits.len();
        let l = self.initial_pairs.len();
        //let mut result = Vec::with_capacity(choice_bits);
        let t_mat: Vec<BitVec> = self
            .initial_pairs
            .iter()
            .map(|(k0, _)| trunc_hash(self.arbitrary_hasher.clone(), output_size, k0))
            .collect();
        for ((_, k1), t) in self.initial_pairs.iter().zip(&t_mat) {
            assert_eq!(t.len(), output_size, "internal error, lengths don't match.");
            let gk = trunc_hash(self.arbitrary_hasher.clone(), output_size, k1);
            assert_eq!(t.len(), gk.len(), "internal error, lengths don't match.");
            assert_eq!(
                t.len(),
                choice_bits.len(),
                "internal error, lengths don't match."
            );
            let u: BitVec = izip!(t, gk, &choice_bits)
                .map(|(t, k, r)| t ^ k ^ r)
                .collect();
            let bytes = u.to_bytes();
            await!(write_data(&mut self.conn, &bytes))?;
        }

        let mut result: Vec<Vec<u8>> = Vec::with_capacity(output_size);

        for i in 0..output_size {
            let y0 = await!(read_data(&mut self.conn))?;
            let y1 = await!(read_data(&mut self.conn))?;
            let ys = [y0, y1];
            assert_eq!(
                ys[0].len(),
                ys[1].len(),
                "String pairs do not have same size"
            );
            let mut bt = BitVec::with_capacity(l);
            for t in &t_mat {
                bt.push(t[i]);
            }
            let mut hasher = self.arbitrary_hasher.clone();
            ArbitraryDigest::input(&mut hasher, &(i as u64).to_be_bytes());
            ArbitraryDigest::input(&mut hasher, &bt.to_bytes());
            let ht = ArbitraryDigest::result(hasher, ys[0].len());
            result.push(
                ys[choice_bits[i] as usize]
                    .iter()
                    .zip(ht)
                    .map(|(ht, y)| y ^ ht)
                    .collect(),
            );
        }
        Ok(result)
    }
}

pub struct IKNPExtendedOTSender<T, A>
where
    T: AsyncRead + AsyncWrite,
    A: ArbitraryDigest + Clone,
{
    pub conn: T,
    arbitrary_hasher: A,
    initial: Vec<Vec<u8>>,
    random_choices: BitVec,
}

impl<T: AsyncRead + AsyncWrite, A: Digest<OutputSize = L> + ArbitraryDigest + Clone, L: ArrayLength<u8>> IKNPExtendedOTSender<T, A> {
    pub async fn new<S, R>(
        conn: T,
        hasher: A,
        crypt: S,
        mut rng: R,
        security_param: usize,
    ) -> Fallible<Self>
    where
        S: SymmetricCryptoProvider<L> + Clone + Copy,
        R: RngCore + CryptoRng
    {
        let l = security_param * 8;
        let mut random_choices = BitVec::with_capacity(security_param);
        let mut initial = Vec::with_capacity(security_param);
        for _ in 0..l {
            let choice: bool = rng.gen();
            random_choices.push(choice);
        }
        let mut base_ot_receiver = await!(SimpleOTReceiver::new(conn, hasher.clone(), crypt, rng))?;
        for choice in &random_choices {
            initial.push(await!(base_ot_receiver.receive(choice as usize, 2))?);
        }
        Ok(IKNPExtendedOTSender {
            conn: base_ot_receiver.conn,
            arbitrary_hasher: hasher,
            initial,
            random_choices,
        })
    }

    pub async fn send(&mut self, values: Vec<(Vec<u8>, Vec<u8>)>) -> Fallible<()> {
        let output_size = values.len();
        let l = self.initial.len();
        let security_parameter = self.initial.len();
        let mut us: Vec<BitVec> = Vec::with_capacity(security_parameter);
        for _ in 0..security_parameter {
            let r = await!(read_data(&mut self.conn))?;
            us.push(bv_truncate(&r, output_size));
        }
        assert_eq!(
            us.len(),
            self.initial.len(),
            "internal error, lengths don't match."
        );
        assert_eq!(
            us.len(),
            self.random_choices.len(),
            "internal error, lengths don't match."
        );
        let q_mat: Vec<BitVec> = izip!(&self.initial, &us, &self.random_choices)
            .map(|(k, u, s)| {
                let gk = trunc_hash(self.arbitrary_hasher.clone(), output_size, k);
                u.iter()
                    .zip(gk)
                    .map(|(u, k)| (((s as u8) * (u as u8)) ^ (k as u8)) == 1)
                    .collect()
            })
            .collect();

        for i in 0..output_size {
            let n = values[i].0.len();
            assert_eq!(n, values[i].1.len(), "String pairs do not have same size");
            let mut qt = BitVec::with_capacity(l);
            for q in &q_mat {
                qt.push(q[i]);
            }
            let mut hasher = self.arbitrary_hasher.clone();
            ArbitraryDigest::input(&mut hasher, &(i as u64).to_be_bytes());
            let mut hasher2 = hasher.clone();
            // TODO make this nicer
            ArbitraryDigest::input(&mut hasher, &qt.to_bytes());
            let hq = ArbitraryDigest::result(hasher, n);
            let y0: Vec<u8> = values[i].0.iter().zip(hq).map(|(x, q)| x ^ q).collect();
            let q2: Vec<u8> = qt
                .to_bytes()
                .iter()
                .zip(self.random_choices.to_bytes())
                .map(|(q, s)| q ^ s)
                .collect();
            ArbitraryDigest::input(&mut hasher2, &q2);
            let shq = ArbitraryDigest::result(hasher2, n);
            let y1: Vec<u8> = values[i].1.iter().zip(shq).map(|(x, q)| x ^ q).collect();
            await!(write_data(&mut self.conn, &y0))?;
            await!(write_data(&mut self.conn, &y1))?;
        }
        Ok(())
    }
}