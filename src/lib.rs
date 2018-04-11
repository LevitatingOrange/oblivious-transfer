extern crate rand;
extern crate curve25519_dalek;

pub mod base_ot;
mod crypto;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
