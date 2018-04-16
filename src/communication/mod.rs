pub mod corrupted;

pub trait BinarySend {
    fn send(&mut self, data: &[u8]);
}

pub trait BinaryReceive {
    fn receive(&mut self) -> Vec<u8>;
}