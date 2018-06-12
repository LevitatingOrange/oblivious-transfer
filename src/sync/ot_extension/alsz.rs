//! Asharaov et al's ot extension with security against active adversaries.

use super::{ExtendedOTReceiver, ExtendedOTSender};
use bit_vec::BitVec;
use common::digest::{ArbitraryDigest, Digest};
use common::util::{bv_truncate, hash, trunc_hash};
use errors::*;
use rand::{CryptoRng, Rng, RngCore};
use std::iter;
use sync::base_ot::BaseOTReceiver;
use sync::base_ot::BaseOTSender;
use sync::communication::{BinaryReceive, BinarySend, GetConn};

pub struct ALSZExtendedOTReceiver<T, A, R>
where
    T: BinaryReceive + BinarySend,
    A: ArbitraryDigest + Digest + Clone,
    R: RngCore + CryptoRng,
{
    conn: T,
    hasher: A,
    rng: R,
    initial_pairs: Vec<(Vec<u8>, Vec<u8>)>,
    security_param: usize,
    stat_security_param: usize,
}

/// security parameter: number of bytes to use
impl<
        T: BinaryReceive + BinarySend,
        A: ArbitraryDigest + Digest + Clone,
        R: RngCore + CryptoRng,
    > ALSZExtendedOTReceiver<T, A, R>
{
    pub fn new<S>(
        hasher: A,
        mut base_ot_sender: S,
        mut rng: R,
        security_param: usize,
        stat_security_param: usize,
    ) -> Result<Self>
    where
        S: BaseOTSender + GetConn<T>,
    {
        // To simplify this protocol both security parameters are specified
        // in bytes and as such have to be multiplied by 8 for certain parts of the protocol.
        let l = (security_param * 8) + (stat_security_param * 8);
        // we initialize a vector with `l` pairs of random seeds (of size `security_param`) and send them with
        // our base-OT primitive to the sender.
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
        Ok(ALSZExtendedOTReceiver {
            hasher: hasher,
            conn: base_ot_sender.get_conn(),
            rng: rng,
            initial_pairs: initial_pairs,
            security_param: security_param,
            stat_security_param: stat_security_param,
        })
    }
}

impl<
        T: BinaryReceive + BinarySend,
        A: ArbitraryDigest + Digest + Clone,
        R: RngCore + CryptoRng,
    > ExtendedOTReceiver for ALSZExtendedOTReceiver<T, A, R>
{
    fn receive(mut self, mut choice_bits: BitVec) -> Result<Vec<Vec<u8>>> {
        // to make things more ergonomic, faster and easier to code both security parametes specify
        // the number of bytes. For the protocol we also need the number of bits
        // so we use `kappa`, `rho` and `l` here as in the protocol of ALSZ2015.
        let kappa = self.security_param * 8;
        let rho = self.stat_security_param * 8;
        let l = kappa + rho;
        let output_size = choice_bits.len();
        let hash_len = output_size + kappa;

        // our seeds get hashed
        let hashed_pairs: Vec<(BitVec, BitVec)> = self
            .initial_pairs
            .iter()
            .map(|(k0, k1)| {
                (
                    trunc_hash(self.hasher.clone(), hash_len, &k0),
                    trunc_hash(self.hasher.clone(), hash_len, &k1),
                )
            })
            .collect();

        // we mask the choices with random bits so the sender can't cheat in the check phase and calculate some of the bits
        choice_bits.extend(iter::repeat_with(|| self.rng.gen_bool(0.5)).take(kappa));

        // now we xor both hashed keys together with our choice bits
        for (hashed_k0, hashed_k1) in hashed_pairs.iter() {
            assert_eq!(
                hashed_k0.len(),
                hash_len,
                "internal error, lengths don't match."
            );
            assert_eq!(
                hashed_k0.len(),
                hashed_k1.len(),
                "internal error, lengths don't match."
            );
            assert_eq!(
                hashed_k0.len(),
                choice_bits.len(),
                "internal error, lengths don't match."
            );
            let u: BitVec = izip!(hashed_k0, hashed_k1, &choice_bits)
                .map(|(t, k, r)| t ^ k ^ r)
                .collect();
            self.conn.send(&u.to_bytes())?;
        }

        // we xor and hash our keys and send them to the sender for verification
        for ((k00, k01), (k10, k11)) in hashed_pairs.iter().zip(hashed_pairs.iter()) {
            self.conn.send(&hash(
                self.hasher.clone(),
                k00.iter().zip(k10).map(|(a, b)| a || b).collect(),
            ))?;
            self.conn.send(&hash(
                self.hasher.clone(),
                k00.iter().zip(k11).map(|(a, b)| a || b).collect(),
            ))?;
            self.conn.send(&hash(
                self.hasher.clone(),
                k01.iter().zip(k10).map(|(a, b)| a || b).collect(),
            ))?;
            self.conn.send(&hash(
                self.hasher.clone(),
                k01.iter().zip(k11).map(|(a, b)| a || b).collect(),
            ))?;
        }

        let mut result: Vec<Vec<u8>> = Vec::with_capacity(output_size);

        // we receive the modified input values of the OT-sender and xor them with the hash of `i` and the transposed first keys
        // this gives us the selected result values.
        for i in 0..output_size {
            let ys = [self.conn.receive()?, self.conn.receive()?];
            if ys[0].len() != ys[1].len() {
                return Err("Received pairs differ in size".into());
            }
            // transpose key matrix
            let mut bt = BitVec::with_capacity(l);
            for j in 0..l {
                bt.push(hashed_pairs[j].0[i]);
            }
            let mut hasher = self.hasher.clone();
            ArbitraryDigest::input(&mut hasher, &(i as u64).to_bytes());
            ArbitraryDigest::input(&mut hasher, &bt.to_bytes());
            let hashed = ArbitraryDigest::result(hasher, ys[0].len());
            result.push(
                ys[choice_bits[i] as usize]
                    .iter()
                    .zip(hashed)
                    .map(|(y, h)| y ^ h)
                    .collect(),
            );
        }
        Ok(result)
    }
}

pub struct ALSZExtendedOTSender<T, A>
where
    T: BinaryReceive + BinarySend,
    A: Digest + ArbitraryDigest + Clone,
{
    conn: T,
    hasher: A,
    initial: Vec<Vec<u8>>,
    random_choices: BitVec,
    security_param: usize,
    stat_security_param: usize,
}

/// security parameter: number of bytes to use
impl<T: BinaryReceive + BinarySend, A: Digest + ArbitraryDigest + Clone>
    ALSZExtendedOTSender<T, A>
{
    pub fn new<S, R>(
        hasher: A,
        mut base_ot_receiver: S,
        mut rng: R,
        security_param: usize,
        stat_security_param: usize,
    ) -> Result<Self>
    where
        S: BaseOTReceiver + GetConn<T>,
        R: RngCore + CryptoRng,
    {
        // To simplify this protocol both security parameters are specified
        // in bytes and as such have to be multiplied by 8 for certain parts of the protocol.
        let l = (security_param * 8) + (stat_security_param * 8);
        // we generate random choices (0 or 1) and use them to receive
        // `l` seeds (of size `security_param`) from the receiver with the base-OT primitive.
        let mut random_choices = BitVec::with_capacity(security_param);
        let mut initial = Vec::with_capacity(security_param);
        for _ in 0..l {
            let mut choice: bool = rng.gen();
            initial.push(base_ot_receiver.receive(choice as usize, 2)?);
            random_choices.push(choice);
        }
        Ok(ALSZExtendedOTSender {
            conn: base_ot_receiver.get_conn(),
            hasher: hasher,
            initial: initial,
            random_choices: random_choices,
            security_param: security_param,
            stat_security_param: stat_security_param,
        })
    }
}

impl<T: BinaryReceive + BinarySend, A: Digest + ArbitraryDigest + Clone> ExtendedOTSender
    for ALSZExtendedOTSender<T, A>
{
    fn send(mut self, values: Vec<(&[u8], &[u8])>) -> Result<()> {
        // to make things more ergonomic, faster and easier to code both security parametes specify
        // the number of bytes. For the protocol we also need the number of bits
        // so we use `kappa`, `rho` and `l` here as in the protocol of ALSZ2015.
        let kappa = self.security_param * 8;
        let rho = self.stat_security_param * 8;
        let l = kappa + rho;
        let output_size = self.random_choices.len();
        let hash_len = output_size + kappa;

        // we receive the xored keys and selection bits
        let mut us: Vec<BitVec> = Vec::with_capacity(l);
        for _ in 0..l {
            us.push(bv_truncate(&self.conn.receive()?, output_size));
        }

        // we verify that the receiver used the same selection bits for all values of u
        for (alpha, beta) in (0..l).zip(0..l) {
            let hs = [
                [self.conn.receive()?, self.conn.receive()?],
                [self.conn.receive()?, self.conn.receive()?],
            ];
            let gk0 = trunc_hash(self.hasher.clone(), hash_len, &self.initial[alpha]);
            let gk1 = trunc_hash(self.hasher.clone(), hash_len, &self.initial[beta]);
            // TODO: faster comparison https://github.com/saschagrunert/fastcmp
            // first check
            {
                let actual =
                    &hs[self.random_choices[alpha] as usize][self.random_choices[beta] as usize];
                let expected = hash(
                    self.hasher.clone(),
                    gk0.iter().zip(&gk1).map(|(a, b)| a || b).collect(),
                );
                println!("actual: {:?}, expected: {:?}", actual, expected);
                if actual.as_slice() != expected.as_slice() {
                    return Err("Cryptographic check (1) failed. Connection corrupted".into());
                }
            }
            // second check
            {
                let actual =
                    &hs[!self.random_choices[alpha] as usize][!self.random_choices[beta] as usize];
                let expected = hash(
                    self.hasher.clone(),
                    izip!(&gk0, &gk1, &us[alpha], &us[beta])
                        .map(|(a, b, u1, u2)| a || b || u1 || u2)
                        .collect(),
                );
                if actual.as_slice() != expected.as_slice() {
                    return Err("Cryptographic check (2) failed. Connection corrupted".into());
                }
            }
            // third check
            if us[alpha] == us[beta] {
                return Err("Cryptographic check (3) failed. Connection corrupted".into());
            }

            let q_mat: Vec<BitVec> = izip!(&self.initial, &us, &self.random_choices)
                .map(|(k, u, s)| {
                    let gk = trunc_hash(self.hasher.clone(), hash_len, k);
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
                let mut hasher = self.hasher.clone();
                ArbitraryDigest::input(&mut hasher, &(i as u64).to_bytes());
                let mut hasher2 = hasher.clone();
                // TODO make this nicer
                ArbitraryDigest::input(&mut hasher, &qt.to_bytes());
                let hq = ArbitraryDigest::result(hasher, n);
                let y0: Vec<u8> = values[i].0.iter().zip(hq).map(|(x, q)| x ^ q).collect();
                let mut q2: Vec<u8> = qt
                    .to_bytes()
                    .iter()
                    .zip(self.random_choices.to_bytes())
                    .map(|(q, s)| q ^ s)
                    .collect();
                ArbitraryDigest::input(&mut hasher2, &q2);
                let shq = ArbitraryDigest::result(hasher2, n);
                let y1: Vec<u8> = values[i].1.iter().zip(shq).map(|(x, q)| x ^ q).collect();
                self.conn.send(&y0)?;
                self.conn.send(&y1)?;
            }
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
    use sync::communication::{BinarySend, BinaryReceive};
    use sync::base_ot::{BaseOTReceiver, BaseOTSender};
    use sync::base_ot::chou::{ChouOrlandiOTReceiver, ChouOrlandiOTSender};
    use sync::crypto::aes::AesCryptoProvider;
    use sync::ot_extension::alsz::{ALSZExtendedOTReceiver, ALSZExtendedOTSender};
    use sync::ot_extension::{ExtendedOTReceiver, ExtendedOTSender};

    #[test]
    fn iknp_test() {
        let len = 100;
        let n = 10;
        let security_param = 16;
        let stat_security_param = 5;

        let choices = generate_random_choices(len);
        let values = generate_random_string_pairs(n, len);

        println!(
            "Testing with pair count={}, string length={}, security parameter (in bytes)={}",
            len, n, security_param
        );

        let choices2 = choices.clone();
        let server = thread::spawn(move || {
            let ot_stream = TcpListener::bind("127.0.0.1:1266")
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
                ALSZExtendedOTReceiver::new(SHA3_256::default(), ot, rng.clone(), security_param, stat_security_param)
                    .unwrap();
            println!("ALSZ receiver creation took {:?}", now.elapsed());
            now = Instant::now();
            let values: Vec<String> = ot_ext
                .receive(choices2)
                .unwrap()
                .into_iter()
                .map(|v| String::from_utf8(v).unwrap())
                .collect();
            println!("ALSZ receive took {:?}", now.elapsed());
            values
        });
        let values2 = values.clone();
        let client = thread::spawn(move || {
            let ot_stream = TcpStream::connect("127.0.0.1:1266").unwrap();
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
                ALSZExtendedOTSender::new(SHA3_256::default(), ot, rng.clone(), security_param, stat_security_param)
                    .unwrap();
            println!("ALSZ sender creation took {:?}", now.elapsed());
            now = Instant::now();
            let values: Vec<(&[u8], &[u8])> = values2
                .iter()
                .map(|(s1, s2)| (s1.as_bytes(), s2.as_bytes()))
                .collect();
            ot_ext.send(values).unwrap();
            println!("ALSZ send took {:?}", now.elapsed());
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
