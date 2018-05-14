#![recursion_limit = "1024"]
#![feature(proc_macro, generators)]
#![feature(iterator_flatten)]

// #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
// extern crate tokio;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
extern crate futures;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
extern crate tungstenite;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
extern crate ring;

#[macro_use]
extern crate arrayref;

extern crate curve25519_dalek;
extern crate digest;
extern crate generic_array;
extern crate rand;
extern crate url;
// TODO: consider tiny keccak
// TODO: rewrite digest trait?
extern crate sha3;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
extern crate rust_sodium;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
extern crate stdweb;

#[macro_use]
extern crate error_chain;
pub mod errors {
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
// TODO channel should be authenticated, but not necessarily confidential, use TLS?
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod async;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod sync;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[no_mangle]
pub extern "C" fn add_one(a: u32) -> u32 {
    a + 1
}
