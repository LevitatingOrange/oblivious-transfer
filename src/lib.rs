#![feature(async_await, await_macro, futures_api, pin)]
#![recursion_limit="128"]

pub mod base_ot;
pub mod crypto;
pub mod util;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod native;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod browser;