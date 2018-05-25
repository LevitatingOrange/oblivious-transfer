use super::{ExtendedOTReceiver, ExtendedOTSender};
use bit_vec::BitVec;
use common::digest::ArbitraryDigest;
use errors::*;
use rand::Rng;
use sync::base_ot::BaseOTReceiver;
use sync::base_ot::BaseOTSender;
use sync::communication::{BinaryReceive, BinarySend};

fn bv_truncate(bytes: &[u8], length: usize) -> BitVec {
    let mut bv = BitVec::from_bytes(bytes);
    bv.truncate(length);
    bv
}

fn trunc_hash<A>(mut hasher: A, length: usize, data: &[u8]) -> BitVec
where
    A: ArbitraryDigest,
{
    hasher.input(data);
    let mut byte_len = length / 8;
    if length % 8 != 0 {
        byte_len += 1;
    }
    let v = hasher.result(byte_len);
    bv_truncate(&v, length)
}

// TODO: This is not ashsarov as it is not malicious-secure (only IKNP)

pub struct AsharovExtendedOTReceiver<T, A>
where
    T: BinaryReceive + BinarySend,
    A: ArbitraryDigest + Clone,
{
    conn: T,
    arbitrary_hasher: A,
    initial_pairs: Vec<(Vec<u8>, Vec<u8>)>,
}

/// security parameter: number of bytes to use
impl<T: BinaryReceive + BinarySend, A: ArbitraryDigest + Clone> AsharovExtendedOTReceiver<T, A> {
    pub fn new<S, R>(
        conn: T,
        arbitrary_hasher: A,
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
            arbitrary_hasher: arbitrary_hasher,
            conn: conn,
            initial_pairs: initial_pairs,
        })
    }
}

impl<T: BinaryReceive + BinarySend, A: ArbitraryDigest + Clone> ExtendedOTReceiver
    for AsharovExtendedOTReceiver<T, A>
{
    fn receive(mut self, choice_bits: BitVec) -> Result<Vec<Vec<u8>>> {
        let output_size = choice_bits.len();
        let l = self.initial_pairs.len() * 8;
        //let mut result = Vec::with_capacity(choice_bits);
        let t_mat: Vec<BitVec> = self.initial_pairs
            .iter()
            .map(|(k0, _)| trunc_hash(self.arbitrary_hasher.clone(), output_size, k0))
            .collect();
        assert_eq!(t_mat[0].len(), output_size, "bitvec lengths don't match");
        for ((_, k1), t) in self.initial_pairs.iter().zip(&t_mat) {
            assert_eq!(t.len(), output_size, "internal error, lengths don't match.");
            let gk = trunc_hash(self.arbitrary_hasher.clone(), output_size, k1);
            let u: BitVec = izip!(t, gk, &choice_bits)
                .map(|(t, k, r)| t ^ k ^ r)
                .collect();
            self.conn.send(&u.to_bytes())?;
        }

        let mut result: Vec<Vec<u8>> = Vec::with_capacity(output_size);

        for i in 0..output_size {
            let y0 = self.conn.receive()?;
            let y1 = self.conn.receive()?;
            let ys = [y0, y1];
            assert_eq!(
                ys[0].len(),
                ys[1].len(),
                "String pairs do not have same size"
            );
            let mut bt = BitVec::with_capacity(l);
            for j in 0..l {
                bt.set(j, t_mat[j][i]);
            }
            let mut hasher = self.arbitrary_hasher.clone();
            hasher.input(&(i as u64).to_bytes());
            hasher.input(&bt.to_bytes());
            let ht = hasher.result(ys[0].len());
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

pub struct AsharovExtendedOTSender<T, A>
where
    T: BinaryReceive + BinarySend,
    A: ArbitraryDigest + Clone,
{
    conn: T,
    arbitrary_hasher: A,
    initial: Vec<Vec<u8>>,
    random_choices: BitVec,
}

/// security parameter: number of bytes to use
impl<T: BinaryReceive + BinarySend, A: ArbitraryDigest + Clone> AsharovExtendedOTSender<T, A> {
    pub fn new<S, R>(
        conn: T,
        arbitrary_hasher: A,
        mut base_ot_receiver: S,
        mut rng: R,
        security_param: usize,
    ) -> Result<Self>
    where
        S: BaseOTReceiver,
        R: Rng,
    {
        let mut random_choices = BitVec::with_capacity(security_param);
        let mut initial = Vec::with_capacity(security_param);
        for i in 0..security_param {
            let mut choice: bool = rng.gen();
            initial[i] = base_ot_receiver.receive(choice as usize, 2)?;
            random_choices.set(i, choice);
        }
        Ok(AsharovExtendedOTSender {
            conn: conn,
            arbitrary_hasher: arbitrary_hasher,
            initial: initial,
            random_choices: random_choices,
        })
    }
}

impl<T: BinaryReceive + BinarySend, A: ArbitraryDigest + Clone> ExtendedOTSender
    for AsharovExtendedOTSender<T, A>
{
    fn send(mut self, values: Vec<(&[u8], &[u8])>) -> Result<()> {
        let output_size = values.len();
        let l = self.initial.len() * 8;
        let security_parameter = self.initial.len();
        let mut us: Vec<BitVec> = Vec::with_capacity(security_parameter);
        for _ in 0..security_parameter {
            us.push(bv_truncate(&self.conn.receive()?, output_size));
        }
        let q_mat: Vec<BitVec> = izip!(&self.initial, &us, &self.random_choices)
            .map(|(k, u, s)| {
                let gk = trunc_hash(self.arbitrary_hasher.clone(), output_size, k);
                u.iter()
                    .zip(gk)
                    .map(|(u, k)| (((s as u8) * (u as u8)) ^ (k as u8)) == 0)
                    .collect()
            })
            .collect();

        for i in 0..output_size {
            let n = values[i].0.len();
            assert_eq!(n, values[i].1.len(), "String pairs do not have same size");
            let mut qt = BitVec::with_capacity(l);
            for j in 0..l {
                qt.set(j, q_mat[j][i]);
            }
            let mut hasher = self.arbitrary_hasher.clone();
            hasher.input(&(i as u64).to_bytes());
            let mut hasher2 = self.arbitrary_hasher.clone();

            // TODO make this nicer
            hasher.input(&qt.to_bytes());
            let hq = hasher.result(n);
            let y0: Vec<u8> = values[i].0.iter().zip(hq).map(|(x, q)| x ^ q).collect();
            let mut q2: Vec<u8> = qt.to_bytes()
                .iter()
                .zip(self.random_choices.to_bytes())
                .map(|(q, s)| q ^ s)
                .collect();
            hasher2.input(&q2);
            let shq = hasher2.result(n);
            let y1: Vec<u8> = values[i].1.iter().zip(shq).map(|(x, q)| x ^ q).collect();
            self.conn.send(&y0)?;
            self.conn.send(&y1)?;
        }
        Ok(())
    }
}
