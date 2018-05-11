#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod async;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod sync;


