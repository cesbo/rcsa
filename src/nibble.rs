use std::ops::BitXor;

use crate::Bit;

#[derive(Debug, Copy, Clone)]
pub struct Nibble(pub Bit, pub Bit, pub Bit, pub Bit);

impl Nibble {
    pub const fn new(b0: Bit, b1: Bit, b2: Bit, b3: Bit) -> Self {
        Nibble(b0, b1, b2, b3)
    }

    pub const N0: Self = Nibble::new(Bit::B0, Bit::B0, Bit::B0, Bit::B0);

    // TODO: unwrap many packets
    #[allow(dead_code)]
    pub fn unwrap(&self) -> u8 {
        self.0.unwrap() | self.1.unwrap() << 1 | self.2.unwrap() << 2 | self.3.unwrap() << 3
    }
}

impl BitXor for Nibble {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Nibble::new(
            self.0 ^ rhs.0,
            self.1 ^ rhs.1,
            self.2 ^ rhs.2,
            self.3 ^ rhs.3,
        )
    }
}
