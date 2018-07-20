//! # An oblivious transfer library in rust and for the web
//!
//! [Oblivious transfer](https://en.wikipedia.org/wiki/Oblivious_transfer) (OT) is an important cryptographic primitive.
//! With it, one could implement any cryptographic protocol (CITE). While for some protocols faster alternatives exist,
//! things like secure function evaluation (SFE) and multi-party computation (MPC) rely on OT.
//!
//! ## Structure
//!
//! At the moment this library is split in two: one synchronous implementation and one asynchronous.
//! The asynchronous part is suited to run on the browser, where only one thread is avalable. The synchronous part can be
//! used on native hosts. As of this writing, incompatibilities between tokio and the futures library forbid
//! asynchronous OT on a native host. We hope to change this as soon as tokio gets updated.  
//!
//! As OT requires some sort of public-key-cryptography (CITE, is this correct like this?) it's speed always is a hindering factor.
//! It has been shown though (CITE) that one can extend a set of basic OT transfers to transfer a much larger amount of data
//! with symmetric crpytography primtives (e.g. hashing).
//!
//! Henceforth we have implemented the OT-variant SimpleOT by Chou and Orlandi (CITE), the
//! semi-honest OT-extension protocol of Ishai et al. (CITE) and a malicious-secure augmentation
//! of the latter by Asharaov et al. (CITE).
//!
//! Recent revelations (CITE) have shown that SimpleOT is not malicious secure and as such
//! composing it with the OT extension of Asharaov will *not* provide security against active adversaries.

#![recursion_limit = "1024"]
#![feature(generators)]
#![feature(iterator_flatten)]
#![feature(int_to_from_bytes)]
#![feature(iterator_repeat_with)]
// TODO: remove this when error_chain crate is fixed
#![allow(renamed_and_removed_lints)]

// #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
// extern crate tokio;

// #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
// extern crate futures;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
extern crate futures_channel;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
extern crate futures_core;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
extern crate futures_util;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
extern crate ring;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
extern crate tungstenite;

#[macro_use]
extern crate arrayref;

extern crate bit_vec;

extern crate curve25519_dalek;
extern crate generic_array;
extern crate rand;
extern crate tiny_keccak;
extern crate url;
#[macro_use]
extern crate itertools;

// #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
// extern crate rust_sodium;

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
// TODO use fast CSPRG, the os_rng used takes very long to generate a value as it creates one from the os entropy pool
// TODO channel should be authenticated, but not necessarily confidential, use TLS?
// TODO transmit length, probably with aes-gcm ad (without any crypto value, would be convinient)
// TODO for now, async only works on the client
#[macro_use]
pub mod common;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod async;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod sync;
