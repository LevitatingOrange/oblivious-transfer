//! # Base OT
//!
//! Implementations of  1-out-of-n oblivious transfer protocols.
//! As these rely on expensive public-key-cryptography one is advised
//! to compose these with extended OT.
// use failure::{Error, Fallible};

pub mod simple_ot;

// /// This is the base trait for sending all base-ot protocols in this library implement.
// pub trait BaseOTSender {
//     async fn send(&mut self, values: Vec<&[u8]>) -> Fallible<()>;
// }

// // TODO: is this interface good?!
// // TODO: should we specify the length as it is
// // transmitted in clear and could be altered
// // either encrypt it or specify l here which we compare to
// /// This is the base trait for sending all base-ot protocols in this library implement.
// pub trait BaseOTReceiver {
//     async fn receive(&mut self, index: usize, n: usize) -> Fallible<Vec<u8>>;
// }
