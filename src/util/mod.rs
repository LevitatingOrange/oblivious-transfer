use byteorder::{BigEndian, ByteOrder};
use failure::{Fallible};
use futures::prelude::*;
use rand::Rng;
use rand::distributions::Alphanumeric;
use bit_vec::BitVec;
use crate::crypto::ArbitraryDigest;

// TODO: or specify length of data? More secure? Does this leak too much?

pub async fn read_data<T: AsyncRead + AsyncReadExt>(conn: &mut T) -> Fallible<Vec<u8>> {
    let mut len_buf = [0; 8];
    await!(conn.read_exact(&mut len_buf))?;
    let len = BigEndian::read_u64(&len_buf) as usize;
    let mut buf = vec![0u8; len];
    await!(conn.read_exact(&mut buf))?;
    Ok(buf)
}

pub async fn write_data<'a, T: AsyncWrite + AsyncWriteExt>(conn: &'a mut T, data: &'a [u8]) -> Fallible<()> {
    let mut len_buf = [0; 8];
    BigEndian::write_u64(&mut len_buf, data.len() as u64);
    await!(conn.write_all(&mut len_buf))?;
    await!(conn.write_all(& data))?;
    Ok(())
}

pub fn generate_random_choices<R: Rng>(rng: &mut R, num: usize) -> BitVec {
    let mut len = num / 8;
    if len % 8 != 0 {
        len += 1;
    }
    let mut v = Vec::with_capacity(len);
    for _ in 0..len {
        v.push(rng.gen());
    }
    bv_truncate(&v, num)
}

pub fn generate_random_strings<R: Rng>(rng: &mut R, n: usize, l: usize) -> Vec<String> {
    let mut values = Vec::with_capacity(n);
    for _ in 0..n {
        let s: String = rng.sample_iter(&Alphanumeric).take(l).collect();
        values.push(s);
    }
    values
}

pub fn generate_random_string_pairs<R: Rng>(rng: &mut R, n: usize, pair_num: usize) -> Vec<(String, String)> {
    let mut values = Vec::with_capacity(pair_num);
    for _ in 0..pair_num {
        let s1: String = rng.sample_iter(&Alphanumeric).take(n).collect();
        let s2: String = rng.sample_iter(&Alphanumeric).take(n).collect();
        values.push((s1, s2));
    }
    values
}

pub fn bv_truncate(bytes: &[u8], length: usize) -> BitVec {
    let mut bv = BitVec::from_bytes(bytes);
    bv.truncate(length);
    bv
}

pub fn trunc_hash<A>(mut hasher: A, length: usize, data: &[u8]) -> BitVec
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