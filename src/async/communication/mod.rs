#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod websockets;
// TODO consider rtc?!
