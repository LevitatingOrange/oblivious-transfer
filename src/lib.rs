#![recursion_limit = "1024"]

extern crate curve25519_dalek;
extern crate digest;
extern crate generic_array;
extern crate rand;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
extern crate rust_sodium;
// TODO: consider tiny keccak
// TODO: rewrite digest trait?
extern crate sha3;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
extern crate tungstenite;
extern crate url;

#[macro_use]
extern crate error_chain;
mod errors {
    // Create the Error, ErrorKind, ResultExt, and Result types
    error_chain!{

        // TODO: foreign_links replace through chain_err
        foreign_links {
            //Fmt(::std::fmt::Error);
            IO(::std::io::Error);
            Websocket(::tungstenite::error::Error) #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))];
        }

        errors {
            PointError {
                description("Received point is invalid")
                display("Received point is invalid")
            }
            // TODO better name?
            CommunicationError {
                description("Error while communicating")
                display("Error while communicating")
            }
        }
    }
}

//extern crate block_cipher_trait;

pub mod base_ot;
pub mod communication;
mod crypto;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[no_mangle]
pub extern "C" fn add_one(a: u32) -> u32 {
    a + 1
}
