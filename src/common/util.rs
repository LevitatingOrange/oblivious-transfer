use super::digest::{ArbitraryDigest, Digest};
use bit_vec::BitVec;
use generic_array::GenericArray;
use rand::{distributions::Alphanumeric, thread_rng, Rng};

// simple macro to make closures and cloning less tedious
// as seen on https://github.com/rust-webplatform/rust-todomvc/blob/master/src/main.rs#L142
macro_rules! enclose {
    ( ($( $x:ident ),*) $y:expr ) => {
        {
            $(let $x = $x.clone();)*
            $y
        }
    };
}

pub fn bv_truncate(bytes: &[u8], length: usize) -> BitVec {
    let mut bv = BitVec::from_bytes(bytes);
    bv.truncate(length);
    bv
}

pub fn create_random_strings(n: usize, l: usize) -> Vec<String> {
    let mut rng = thread_rng();
    let mut values = Vec::with_capacity(n);
    for _ in 0..n {
        let s: String = rng.sample_iter(&Alphanumeric).take(l).collect();
        values.push(s);
    }
    values
}

pub fn generate_random_string_pairs(n: usize, pair_num: usize) -> Vec<(String, String)> {
    let mut rng = thread_rng();
    let mut values = Vec::with_capacity(pair_num);
    for _ in 0..pair_num {
        let s1: String = rng.sample_iter(&Alphanumeric).take(n).collect();
        let s2: String = rng.sample_iter(&Alphanumeric).take(n).collect();
        values.push((s1, s2));
    }
    values
}

pub fn generate_random_choices(num: usize) -> BitVec {
    let mut rng = thread_rng();
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

pub fn hash<D>(mut hasher: D, val: BitVec) -> GenericArray<u8, D::OutputSize>
where
    D: Digest,
{
    hasher.input(&val.to_bytes());
    hasher.result()
}