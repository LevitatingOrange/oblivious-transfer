extern crate rand;

use rand::distributions::range::Range;
use rand::distributions::Distribution;
use rand::{ChaChaRng, CryptoRng, FromEntropy, RngCore};
use std::mem::transmute;
use std::ops::{Add, AddAssign, Mul, Neg, Sub};

// modulus is < 2^63 so addition never overflows
// this is just so this small example is easier
// in a correct implementation this has to
// be implemented correctly
pub const MODULUS: u64 = 9223372036854775783;
pub const K: usize = 64;
pub const SECURITY_PARAM: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GFElement(pub u64);

impl GFElement {
    pub fn new(val: u64) -> GFElement {
        GFElement(val % MODULUS)
    }

    pub fn random<R: CryptoRng + RngCore>(rng: &mut R) -> GFElement {
        let range = Range::new(0, MODULUS);
        GFElement(range.sample(rng))
    }

    pub fn from_bytes(v: Vec<u8>) -> Self {
        assert_eq!(
            v.len(),
            8,
            "Vector has to have 8 bytes to be converted to u64"
        );
        let mut bytes: [u8; 8] = Default::default();
        bytes.copy_from_slice(&v);

        let val = unsafe { u64::from_be(transmute(bytes)) };
        GFElement(val)
    }
    pub fn to_bytes(self) -> Vec<u8> {
        let bytes: [u8; 8] = unsafe { transmute(self.0.to_be()) };
        bytes.to_vec()
    }
}

impl Add for GFElement {
    type Output = Self;
    fn add(self, other: GFElement) -> Self {
        GFElement((self.0 + other.0) % MODULUS)
    }
}

impl AddAssign for GFElement {
    fn add_assign(&mut self, other: GFElement) {
        (*self).0 = (self.0 + other.0) % MODULUS;
    }
}

impl Mul for GFElement {
    type Output = Self;
    fn mul(self, rhs: GFElement) -> GFElement {
        let r = ((self.0 as u128) * (rhs.0 as u128)) % (MODULUS as u128);
        GFElement(r as u64)
    }
}

impl Neg for GFElement {
    type Output = Self;
    fn neg(self) -> Self {
        GFElement(MODULUS - (self.0))
    }
}

impl Sub for GFElement {
    type Output = Self;
    fn sub(self, other: GFElement) -> Self {
        self + (-other)
    }
}
