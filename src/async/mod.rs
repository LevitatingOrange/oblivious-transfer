pub mod base_ot;
pub mod communication;
pub mod crypto;
pub mod ot_extension;

// TODO: maybe replace Mutexs with simple get_mut().unwrap() calls as
// in reality only one mutable reference should be open
