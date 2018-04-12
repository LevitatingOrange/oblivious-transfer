extern crate rand;
extern crate curve25519_dalek;
extern crate digest;
extern crate sha3;

pub mod base_ot;
mod crypto;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
