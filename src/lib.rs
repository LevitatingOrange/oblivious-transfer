extern crate curve25519_dalek;
extern crate digest;
extern crate generic_array;
extern crate rand;
extern crate sha3;
#[cfg(not(all(target_arch="wasm32", target_os="unknown")))]
extern crate rust_sodium;

//extern crate block_cipher_trait;

pub mod base_ot;
pub mod communication;
mod crypto;

#[cfg(all(target_arch="wasm32", target_os="unknown"))]
#[no_mangle]
pub extern fn add_one(a: u32) -> u32 {
    a + 1
}
