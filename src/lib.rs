extern crate rand;
extern crate curve25519_dalek;
extern crate digest;
extern crate sha3;
//extern crate block_cipher_trait;

pub mod base_ot;
mod communication;
mod crypto;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
