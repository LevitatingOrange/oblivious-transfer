//! chou and orlandis 1-out-of-n OT [https://eprint.iacr.org/2015/267.pdf]

use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE, EIGHT_TORSION};
use curve25519_dalek::edwards::*;
use curve25519_dalek::scalar::*;

use common::digest::Digest;
use errors::*;
use generic_array::{ArrayLength, GenericArray};
use rand::{CryptoRng, RngCore};
use std::iter::Iterator;
use std::vec::Vec;
use sync::communication::{BinaryReceive, BinarySend, GetConn};
use sync::crypto::{SymmetricDecryptor, SymmetricEncryptor};

fn receive_point<T>(conn: &mut T) -> Result<EdwardsPoint>
where
    T: BinaryReceive,
{
    let v = conn.receive()?;
    if v.len() != 32 {
        return Err(ErrorKind::PointError.into());
    }
    let mut buf: [u8; 32] = Default::default();
    buf.copy_from_slice(&v);
    CompressedEdwardsY(buf)
        .decompress()
        .ok_or_else(|| ErrorKind::PointError.into())
}

fn send_point<T>(conn: &mut T, p: EdwardsPoint) -> Result<()>
where
    T: BinarySend,
{
    conn.send(p.compress().as_bytes())?;
    Ok(())
}

#[derive(Clone)]
pub struct ChouOrlandiOTSender<T, D, L, S>
where
    T: BinarySend + BinaryReceive,
    D: Digest<OutputSize = L> + Clone,
    L: ArrayLength<u8>,
    S: SymmetricEncryptor<L>,
{
    pub conn: T,
    hasher: D,
    encryptor: S,
    y: Scalar,
    t64: EdwardsPoint,
}

impl<
        T: BinaryReceive + BinarySend,
        D: Digest<OutputSize = L> + Clone,
        L: ArrayLength<u8>,
        S: SymmetricEncryptor<L>,
    > GetConn<T> for ChouOrlandiOTSender<T, D, L, S>
{
    fn get_conn(self) -> T {
        self.conn
    }
}

// TODO: parallelize the protocol

impl<
        T: BinarySend + BinaryReceive,
        D: Digest<OutputSize = L> + Clone,
        L: ArrayLength<u8>,
        S: SymmetricEncryptor<L>,
    > ChouOrlandiOTSender<T, D, L, S>
{
    pub fn new<R>(mut conn: T, mut hasher: D, encryptor: S, mut rng: R) -> Result<Self>
    where
        R: RngCore + CryptoRng,
    {
        let y = Scalar::random(&mut rng);
        let mut s = &y * &ED25519_BASEPOINT_TABLE;

        // we dont send s directly, instead we add a point from the eight torsion subgroup.
        // This enables the receiver to verify that s is in the subgroup of the twisted edwards curve
        // 25519 of Bernstein et al. [TODO: CITE]
        send_point(&mut conn, s + EIGHT_TORSION[1])?;
        // see ChouOrlandiOTReceiver::new for discussion of why to multiply by the cofactor (i.e. 8)
        s = s.mul_by_cofactor();
        hasher.input(s.compress().as_bytes());
        Ok(ChouOrlandiOTSender {
            conn,
            hasher,
            encryptor,
            y,
            t64: (y * s).mul_by_cofactor(),
        })
    }

    pub fn compute_keys(&mut self, n: u64) -> Result<Vec<GenericArray<u8, L>>> {
        let mut hasher = self.hasher.clone();
        let r = receive_point(&mut self.conn)?.mul_by_cofactor();
        // seed the hash function with s and r in its compressed form
        hasher.input(r.compress().as_bytes());
        Ok((0..n)
            .map(|j| {
                // hash p=64yR - 64jT, this will reduce to 64xS if c == j, but as x is only known
                // to the receiver (provided the discrete logartihm problem is hard in our curve)
                // the sender does not know c.
                let p = self.y * r - Scalar::from_u64(j) * self.t64;
                let mut hasher = hasher.clone();
                hasher.input(p.compress().as_bytes());
                hasher.result()
            })
            .collect())
    }
}

impl<
        T: BinaryReceive + BinarySend,
        D: Digest<OutputSize = L> + Clone,
        L: ArrayLength<u8>,
        S: SymmetricEncryptor<L>,
    > super::BaseOTSender for ChouOrlandiOTSender<T, D, L, S>
{
    fn send(&mut self, values: Vec<&[u8]>) -> Result<()> {
        let keys = self.compute_keys(values.len() as u64)?;
        // TODO: make this idiomatic, compute_keys, is copy ok here?
        for (key, value) in keys.into_iter().zip(values) {
            let mut buf = value.to_owned();
            buf = self.encryptor.encrypt(&key, buf)?;
            self.conn.send(&buf)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct ChouOrlandiOTReceiver<T, R, D, L, S>
where
    T: BinaryReceive + BinarySend,
    R: RngCore + CryptoRng,
    D: Digest<OutputSize = L> + Clone,
    L: ArrayLength<u8>,
    S: SymmetricDecryptor<L>,
{
    pub conn: T,
    hasher: D,
    decryptor: S,
    rng: R,
    s8: EdwardsPoint,
}

impl<
        T: BinaryReceive + BinarySend,
        R: RngCore + CryptoRng,
        D: Digest<OutputSize = L> + Clone,
        L: ArrayLength<u8>,
        S: SymmetricDecryptor<L>,
    > ChouOrlandiOTReceiver<T, R, D, L, S>
{
    pub fn new(mut conn: T, mut hasher: D, decryptor: S, rng: R) -> Result<Self> {
        let mut s = receive_point(&mut conn)?;
        // as we've added a point from the eight torsion subgroup to s before sending,
        // by multiplying with the cofactor (i.e. 8, i.e. the order of the eight torsion subgroup)
        // we get [8]s and can be sure that the received value is indeed in the subgroup
        // of our 25519 twisted edwards curve. To avoid a costly division operation (by 8), we
        // operate on 8 and later on 64 times our initial values. [TODO: Cite]
        s = s.mul_by_cofactor();
        hasher.input(s.compress().as_bytes());
        Ok(ChouOrlandiOTReceiver {
            conn,
            hasher,
            decryptor,
            rng,
            s8: s,
        })
    }

    pub fn compute_key(&mut self, c: u64) -> Result<GenericArray<u8, L>> {
        let mut hasher = self.hasher.clone();
        let x = Scalar::random(&mut self.rng);
        let r = Scalar::from_u64(c) * self.s8 + (&x * &ED25519_BASEPOINT_TABLE).mul_by_cofactor();

        send_point(&mut self.conn, r + EIGHT_TORSION[1])?;

        // seed the hash function with s and r in it's compressed form
        hasher.input(r.mul_by_cofactor().compress().as_bytes());

        // hash p = 64xS
        // TODO: is it better to use mul_by_cofactor?
        let p = (x * Scalar::from_u64(8)) * self.s8;
        hasher.input(p.compress().as_bytes());
        Ok(hasher.result())
    }
}

impl<
        T: BinaryReceive + BinarySend,
        R: RngCore + CryptoRng,
        D: Digest<OutputSize = L> + Clone,
        L: ArrayLength<u8>,
        S: SymmetricDecryptor<L>,
    > super::BaseOTReceiver for ChouOrlandiOTReceiver<T, R, D, L, S>
{
    fn receive(&mut self, index: usize, n: usize) -> Result<Vec<u8>> {
        let key = self.compute_key(index as u64)?;
        let mut buffers: Vec<Vec<u8>> = Default::default();
        for _ in 0..n {
            buffers.push(self.conn.receive()?);
        }
        let buf = self.decryptor.decrypt(&key, buffers.remove(index))?;
        Ok(buf)
    }
}

impl<
        T: BinaryReceive + BinarySend,
        R: RngCore + CryptoRng,
        D: Digest<OutputSize = L> + Clone,
        L: ArrayLength<u8>,
        S: SymmetricDecryptor<L>,
    > GetConn<T> for ChouOrlandiOTReceiver<T, R, D, L, S>
{
    fn get_conn(self) -> T {
        self.conn
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use common::digest::sha3::SHA3_256;
    use common::util::create_random_strings;
    use rand::{thread_rng, ChaChaRng, FromEntropy, Rng};
    use std::net::TcpListener;
    use std::net::TcpStream;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    use std::time::Instant;
    use sync::base_ot::{BaseOTReceiver, BaseOTSender};
    use sync::communication::corrupted::CorruptedChannel;
    use sync::crypto::{
        aes::AesCryptoProvider,
        dummy::DummyCryptoProvider, //sodium::SodiumCryptoProvider,
    };
    use tungstenite::client::connect;
    use tungstenite::server::accept;
    use url::Url;

    macro_rules! generate_communication_test {
        ($client_conn:expr, $server_conn:expr, $digest:expr, $enc:expr, $dec:expr) => {
            let n: usize = 10;
            let l = 512;
            let c: u64 = thread_rng().gen_range(0, n as u64);

            let values = Arc::new(create_random_strings(n, l));
            let vals = Arc::clone(&values);
            let vals2 = Arc::clone(&values);

            let server = thread::spawn(move || {
                let vals: Vec<&[u8]> = vals.iter().map(|s| s.as_bytes()).collect();
                let rng = ChaChaRng::from_entropy();
                let mut ot =
                    ChouOrlandiOTSender::new($client_conn, $digest, $enc, rng).unwrap();
                ot.send(vals).unwrap()
            });
            let client = thread::spawn(move || {
                // TODO: make this better
                thread::sleep(Duration::new(1, 0));
                let rng = ChaChaRng::from_entropy();
                let mut ot =
                    ChouOrlandiOTReceiver::new($server_conn, $digest, $dec, rng).unwrap();
                ot.receive(c as usize, n).unwrap()
            });
            let _ = server.join().unwrap();
            let result = String::from_utf8(client.join().unwrap()).unwrap();
            assert_eq!(
                result, vals2[c as usize],
                "result incorrect with following index: {} and values: {:?}",
                c, values
            );
        };
    }

    #[test]
    pub fn chou_ot_key_exchange() {
        let index = 3;
        let server = thread::spawn(move || {
            let stream = TcpListener::bind("127.0.0.1:1236")
                .unwrap()
                .accept()
                .unwrap()
                .0;
            let rng = ChaChaRng::from_entropy();
            let mut now = Instant::now();
            let mut ot = ChouOrlandiOTSender::new(
                stream,
                SHA3_256::default(),
                DummyCryptoProvider::default(),
                rng,
            ).unwrap();
            println!("Chou ot send new took {:?}", now.elapsed());
            now = Instant::now();
            let keys = ot.compute_keys(10).unwrap();
            println!("Chou ot key send took {:?}", now.elapsed());
            keys
        });
        let client = thread::spawn(move || {
            let stream = TcpStream::connect("127.0.0.1:1236").unwrap();
            let rng = ChaChaRng::from_entropy();
            let mut now = Instant::now();
            let mut ot = ChouOrlandiOTReceiver::new(
                stream,
                SHA3_256::default(),
                DummyCryptoProvider::default(),
                rng,
            ).unwrap();
            println!("Chou ot receive new took {:?}", now.elapsed());
            now = Instant::now();
            let key = ot.compute_key(index).unwrap();
            println!("Chou ot key receive took {:?}", now.elapsed());
            key
        });
        let hashes_sender = server.join().unwrap();
        let hash_receiver = client.join().unwrap();

        assert_eq!(hashes_sender[index as usize], hash_receiver)
    }

    #[test]
    fn chou_ot_key_exchange_multiple() {
        static INDICES: [u64; 5] = [5, 0, 9, 3, 7];

        let server = thread::spawn(move || {
            let mut ot = ChouOrlandiOTSender::new(
                TcpListener::bind("127.0.0.1:1237")
                    .unwrap()
                    .accept()
                    .unwrap()
                    .0,
                SHA3_256::default(),
                DummyCryptoProvider::default(),
                ChaChaRng::from_entropy(),
            ).unwrap();
            INDICES
                .iter()
                .map(move |i| ot.compute_keys(10).unwrap()[*i as usize])
                .collect()
        });

        let client = thread::spawn(move || {
            let mut ot = ChouOrlandiOTReceiver::new(
                TcpStream::connect("127.0.0.1:1237").unwrap(),
                SHA3_256::default(),
                DummyCryptoProvider::default(),
                ChaChaRng::from_entropy(),
            ).unwrap();
            INDICES
                .iter()
                .map(move |i| ot.compute_key(*i).unwrap())
                .collect()
        });

        let hashes_sender: Vec<_> = server.join().unwrap();
        let hashes_receiver: Vec<_> = client.join().unwrap();

        for (send_hash, recv_hash) in hashes_sender.iter().zip(hashes_receiver.iter()) {
            assert_eq!(send_hash, recv_hash);
        }
    }

    #[test]
    fn chou_ot_key_exchange_c0() {
        // given c == 0 and a poor implementation an attacker can infer that c is 0 given the transmitted R
        let server = thread::spawn(move || {
            let mut ot = ChouOrlandiOTSender::new(
                TcpListener::bind("127.0.0.1:1238")
                    .unwrap()
                    .accept()
                    .unwrap()
                    .0,
                SHA3_256::default(),
                DummyCryptoProvider::default(),
                ChaChaRng::from_entropy(),
            ).unwrap();
            ot.compute_keys(10).unwrap()
        });

        // if the transmitted R is wrongly calculated (i.e. c*t + R, where t is an eight torsion point,
        // see ChouOrlandiOTReceiver::new for why we add this eight torsion point), then the point is torsion free
        // if c = 0 and an attacker can infer that c is indeed 0

        fn eavesdrop(_: &mut (), buf: &[u8]) {
            let mut new_buf: [u8; 32] = Default::default();
            new_buf.copy_from_slice(buf);
            assert!(
                !CompressedEdwardsY(new_buf)
                    .decompress()
                    .unwrap()
                    .is_torsion_free()
            )
        }

        let client = thread::spawn(move || {
            let corrupted_channel = CorruptedChannel::new_eavesdrop(
                TcpStream::connect("127.0.0.1:1238").unwrap(),
                (),
                eavesdrop,
            );
            let mut ot = ChouOrlandiOTReceiver::new(
                corrupted_channel,
                SHA3_256::default(),
                DummyCryptoProvider::default(),
                ChaChaRng::from_entropy(),
            ).unwrap();
            ot.compute_key(0).unwrap()
        });
        let hashes_sender = server.join().unwrap();
        let hash_receiver = client.join().unwrap();

        assert_eq!(hashes_sender[0], hash_receiver)
    }

    #[test]
    fn tcp_with_dummy_encryption() {
        generate_communication_test!(
            TcpListener::bind("127.0.0.1:1239")
                .unwrap()
                .accept()
                .unwrap()
                .0,
            TcpStream::connect("127.0.0.1:1239").unwrap(),
            SHA3_256::default(),
            DummyCryptoProvider::default(),
            DummyCryptoProvider::default()
        );
    }

    // #[test]
    // fn tcp_with_sodium_encryption() {
    //     generate_communication_test!(
    //         TcpListener::bind("127.0.0.1:1240")
    //             .unwrap()
    //             .accept()
    //             .unwrap()
    //             .0,
    //         TcpStream::connect("127.0.0.1:1240").unwrap(),
    //         SHA3_256::default(),
    //         SodiumCryptoProvider::default(),
    //         SodiumCryptoProvider::default()
    //     );
    // }

    #[test]
    fn websocket_with_dummy_encryption() {
        generate_communication_test!(
            accept(
                TcpListener::bind("127.0.0.1:1241")
                    .unwrap()
                    .accept()
                    .unwrap()
                    .0
            ).unwrap(),
            connect(Url::parse("ws://localhost:1241/socket").unwrap())
                .unwrap()
                .0,
            SHA3_256::default(),
            DummyCryptoProvider::default(),
            DummyCryptoProvider::default()
        );
    }

    // #[test]
    // fn websocket_with_sodium_encryption() {
    //     generate_communication_test!(
    //         accept(
    //             TcpListener::bind("127.0.0.1:1242")
    //                 .unwrap()
    //                 .accept()
    //                 .unwrap()
    //                 .0
    //         ).unwrap(),
    //         connect(Url::parse("ws://localhost:1242/socket").unwrap())
    //             .unwrap()
    //             .0,
    //         SHA3_256::default(),
    //         SodiumCryptoProvider::default(),
    //         SodiumCryptoProvider::default()
    //     );
    // }

    #[test]
    fn websocket_with_aes_gcm_encryption() {
        generate_communication_test!(
            accept(
                TcpListener::bind("127.0.0.1:1243")
                    .unwrap()
                    .accept()
                    .unwrap()
                    .0
            ).unwrap(),
            connect(Url::parse("ws://localhost:1243/socket").unwrap())
                .unwrap()
                .0,
            SHA3_256::default(),
            AesCryptoProvider::default(),
            AesCryptoProvider::default()
        );
    }

}
