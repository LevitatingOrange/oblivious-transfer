//! Ishai et al's semi-honest ot extension protocol.

use super::{ExtendedOTReceiver, ExtendedOTSender};
use bit_vec::BitVec;
use common::digest::ArbitraryDigest;
use common::util::{bv_truncate, trunc_hash};
use errors::*;
use rand::{CryptoRng, Rng, RngCore};
use sync::base_ot::BaseOTReceiver;
use sync::base_ot::BaseOTSender;
use sync::communication::{BinaryReceive, BinarySend, GetConn};

pub struct IKNPExtendedOTReceiver<T, A>
where
    T: BinaryReceive + BinarySend,
    A: ArbitraryDigest + Clone,
{
    conn: T,
    arbitrary_hasher: A,
    initial_pairs: Vec<(Vec<u8>, Vec<u8>)>,
}

impl<T: BinaryReceive + BinarySend, A: ArbitraryDigest + Clone> GetConn<T>
    for IKNPExtendedOTReceiver<T, A>
{
    fn get_conn(self) -> T {
        return self.conn;
    }
}

/// security parameter: number of bytes to use
impl<T: BinaryReceive + BinarySend, A: ArbitraryDigest + Clone> IKNPExtendedOTReceiver<T, A> {
    pub fn new<S, R>(
        arbitrary_hasher: A,
        mut base_ot_sender: S,
        mut rng: R,
        security_param: usize,
    ) -> Result<Self>
    where
        S: BaseOTSender + GetConn<T>,
        R: RngCore + CryptoRng,
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
            base_ot_sender.send(vec![&k0, &k1])?;
            initial_pairs.push((k0, k1));
        }
        Ok(IKNPExtendedOTReceiver {
            arbitrary_hasher: arbitrary_hasher,
            conn: base_ot_sender.get_conn(),
            initial_pairs: initial_pairs,
        })
    }
}

impl<T: BinaryReceive + BinarySend, A: ArbitraryDigest + Clone> ExtendedOTReceiver
    for IKNPExtendedOTReceiver<T, A>
{
    fn receive(&mut self, choice_bits: &BitVec) -> Result<Vec<Vec<u8>>> {
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
            let u: BitVec = izip!(t, gk, choice_bits)
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
                bt.push(t_mat[j][i]);
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

pub struct IKNPExtendedOTSender<T, A>
where
    T: BinaryReceive + BinarySend,
    A: ArbitraryDigest + Clone,
{
    conn: T,
    arbitrary_hasher: A,
    initial: Vec<Vec<u8>>,
    random_choices: BitVec,
}

impl<T: BinaryReceive + BinarySend, A: ArbitraryDigest + Clone> GetConn<T>
    for IKNPExtendedOTSender<T, A>
{
    fn get_conn(self) -> T {
        return self.conn;
    }
}

/// security parameter: number of bytes to use
impl<T: BinaryReceive + BinarySend, A: ArbitraryDigest + Clone> IKNPExtendedOTSender<T, A> {
    pub fn new<S, R>(
        arbitrary_hasher: A,
        mut base_ot_receiver: S,
        mut rng: R,
        security_param: usize,
    ) -> Result<Self>
    where
        S: BaseOTReceiver + GetConn<T>,
        R: RngCore + CryptoRng,
    {
        let l = security_param * 8;
        let mut random_choices = BitVec::with_capacity(security_param);
        let mut initial = Vec::with_capacity(security_param);
        for _ in 0..l {
            let mut choice: bool = rng.gen();
            initial.push(base_ot_receiver.receive(choice as usize, 2)?);
            random_choices.push(choice);
        }
        Ok(IKNPExtendedOTSender {
            conn: base_ot_receiver.get_conn(),
            arbitrary_hasher: arbitrary_hasher,
            initial: initial,
            random_choices: random_choices,
        })
    }
}

impl<T: BinaryReceive + BinarySend, A: ArbitraryDigest + Clone> ExtendedOTSender
    for IKNPExtendedOTSender<T, A>
{
    fn send(&mut self, values: Vec<(&[u8], &[u8])>) -> Result<()> {
        let output_size = values.len();
        let l = self.initial.len();
        let security_parameter = self.initial.len();
        let mut us: Vec<BitVec> = Vec::with_capacity(security_parameter);
        for _ in 0..security_parameter {
            us.push(bv_truncate(&self.conn.receive()?, output_size));
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
            for j in 0..l {
                qt.push(q_mat[j][i]);
            }
            let mut hasher = self.arbitrary_hasher.clone();
            hasher.input(&(i as u64).to_bytes());
            let mut hasher2 = hasher.clone();
            // TODO make this nicer
            hasher.input(&qt.to_bytes());
            let hq = hasher.result(n);
            let y0: Vec<u8> = values[i].0.iter().zip(hq).map(|(x, q)| x ^ q).collect();
            let mut q2: Vec<u8> = qt
                .to_bytes()
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

#[cfg(test)]
mod tests {

    use common::digest::sha3::SHA3_256;
    use common::util::{generate_random_choices, generate_random_string_pairs};
    use rand::ChaChaRng;
    use rand::FromEntropy;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Instant;
    use sync::base_ot::chou::{ChouOrlandiOTReceiver, ChouOrlandiOTSender};
    use sync::crypto::aes::AesCryptoProvider;
    use sync::ot_extension::iknp::{IKNPExtendedOTReceiver, IKNPExtendedOTSender};
    use sync::ot_extension::{ExtendedOTReceiver, ExtendedOTSender};

    #[test]
    fn iknp_test() {
        let len = 100;
        let n = 200;
        let security_param = 16;

        let choices = generate_random_choices(len);
        let values = generate_random_string_pairs(n, len);

        println!(
            "Testing with pair count={}, string length={}, security parameter (in bytes)={}",
            len, n, security_param
        );

        let choices2 = choices.clone();
        let server = thread::spawn(move || {
            let ot_stream = TcpListener::bind("127.0.0.1:1256")
                .unwrap()
                .accept()
                .unwrap()
                .0;
            let rng = ChaChaRng::from_entropy();
            let mut now = Instant::now();
            let ot = ChouOrlandiOTSender::new(
                ot_stream,
                SHA3_256::default(),
                AesCryptoProvider::default(),
                rng.clone(),
            ).unwrap();
            println!("Chou ot sender creation took {:?}", now.elapsed());
            now = Instant::now();
            let ot_ext =
                IKNPExtendedOTReceiver::new(SHA3_256::default(), ot, rng.clone(), security_param)
                    .unwrap();
            println!("IKNP receiver creation took {:?}", now.elapsed());
            now = Instant::now();
            let values: Vec<String> = ot_ext
                .receive(&choices2)
                .unwrap()
                .into_iter()
                .map(|v| String::from_utf8(v).unwrap())
                .collect();
            println!("IKNP receive took {:?}", now.elapsed());
            values
        });
        let values2 = values.clone();
        let client = thread::spawn(move || {
            let ot_stream = TcpStream::connect("127.0.0.1:1256").unwrap();
            let rng = ChaChaRng::from_entropy();
            let mut now = Instant::now();
            let ot = ChouOrlandiOTReceiver::new(
                ot_stream,
                SHA3_256::default(),
                AesCryptoProvider::default(),
                rng.clone(),
            ).unwrap();
            println!("chou ot receiver creation took {:?}", now.elapsed());
            now = Instant::now();
            let ot_ext =
                IKNPExtendedOTSender::new(SHA3_256::default(), ot, rng.clone(), security_param)
                    .unwrap();
            println!("IKNP sender creation took {:?}", now.elapsed());
            now = Instant::now();
            let values: Vec<(&[u8], &[u8])> = values2
                .iter()
                .map(|(s1, s2)| (s1.as_bytes(), s2.as_bytes()))
                .collect();
            ot_ext.send(values).unwrap();
            println!("IKNP send took {:?}", now.elapsed());
        });
        let rec_values = server.join().unwrap();
        client.join().unwrap();

        for (i, choice) in choices.iter().enumerate() {
            if choice {
                assert_eq!(values[i].1, rec_values[i], "Values differ at index {}", i);
            } else {
                assert_eq!(values[i].0, rec_values[i], "Values differ at index {}", i);
            }
        }
    }
}
