//! A small deterministic random number generator, shared by the tests.
#![allow(dead_code)]

/// xorshift64*, so failures are reproducible from the seed. The seed must be
/// non-zero.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A value in `0..n`, or 0 if `n` is 0.
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    pub fn byte(&mut self) -> u8 {
        self.next() as u8
    }

    pub fn word(&mut self) -> u32 {
        self.next() as u32
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }

    /// True with the given probability in percent.
    pub fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

/// The number of iterations to run: the value of the environment variable
/// `var`, or `default`.
pub fn iterations(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
