use std::ops::{
    BitAnd,
    BitOr,
    BitXor,
    Not,
    Shl,
};

#[derive(Debug, Copy, Clone)]
pub struct Bit(u8);

impl Bit {
    pub const fn new(bit: u8) -> Self {
        Bit(bit & 0x01)
    }

    pub const B0: Bit = Bit::new(0);

    // TODO: many packets
    pub fn unwrap(&self) -> u8 {
        self.0
    }
}

impl BitAnd for Bit {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Bit(self.0 & rhs.0)
    }
}

impl BitOr for Bit {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Bit(self.0 | rhs.0)
    }
}

impl BitXor for Bit {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Bit(self.0 ^ rhs.0)
    }
}

impl Not for Bit {
    type Output = Bit;

    fn not(self) -> Self::Output {
        Bit((!self.0) & 0x01)
    }
}

impl Shl<usize> for Bit {
    type Output = Self;

    fn shl(self, rsh: usize) -> Self::Output {
        Bit(self.0 << rsh)
    }
}
