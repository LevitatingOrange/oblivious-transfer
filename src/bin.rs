#![feature(async_await, await_macro, futures_api)]
use futures::future::Future;

#[macro_use]
extern crate tokio;

#[macro_use] 
extern crate failure;


fn main() {
    // And we are async...
    tokio::run_async(async {
        println!("Hello");
    });
}