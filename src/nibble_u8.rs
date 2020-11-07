use {
    std::{
        ops::{
            BitXor,
        },
    },
};


#[derive(Debug, Copy, Clone)]
pub struct Nibble (pub u8, pub u8, pub u8, pub u8);


impl Nibble {
    pub const fn new(b0: u8, b1: u8, b2: u8, b3: u8) -> Self {
        Nibble (b0, b1, b2, b3)
    }

    pub const X00: Self = Nibble::new(0, 0, 0, 0);

    pub fn rotate_left(&self) -> Self {
        Nibble (self.3, self.0, self.1, self.2)
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


impl From<u8> for Nibble {
    fn from(v: u8) -> Self {
        Nibble (
            (v >> 0) & 1,
            (v >> 1) & 1,
            (v >> 2) & 1,
            (v >> 3) & 1,
        )
    }
}
