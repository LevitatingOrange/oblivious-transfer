use byteorder::{BigEndian, ByteOrder};
use failure::{Fallible};
use futures::prelude::*;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

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

pub fn generate_random_strings(n: usize, l: usize) -> Vec<String> {
    let mut rng = thread_rng();
    let mut values = Vec::with_capacity(n);
    for _ in 0..n {
        let s: String = rng.sample_iter(&Alphanumeric).take(l).collect();
        values.push(s);
    }
    values
}