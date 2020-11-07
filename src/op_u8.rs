//! Single packet operations


use {
    std::{
        ops::{
            BitAnd,
            BitAndAssign,
            BitOr,
            BitOrAssign,
            BitXor,
            BitXorAssign,
        },
    },
};


#[derive(Debug, Copy, Clone)]
pub struct Nibble (pub u8, pub u8, pub u8, pub u8);


impl Nibble {
    pub const fn new(b0: u8, b1: u8, b2: u8, b3: u8) -> Self {
        Nibble (
            b0 & 0x01,
            b1 & 0x01,
            b2 & 0x01,
            b3 & 0x01,
        )
    }

    pub const X00: Self = Nibble::new(0, 0, 0, 0);

    pub fn rotate_left(&mut self) {
        let tmp = self.3;
        self.3 = self.2;
        self.2 = self.1;
        self.1 = self.0;
        self.0 = tmp;
    }
}


impl BitAnd for Nibble {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self (
            self.0 & rhs.0,
            self.1 & rhs.1,
            self.2 & rhs.2,
            self.3 & rhs.3,
        )
    }
}


impl BitAndAssign for Nibble {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
        self.1 &= rhs.1;
        self.2 &= rhs.2;
        self.3 &= rhs.3;
    }
}


impl BitOr for Nibble {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self (
            self.0 | rhs.0,
            self.1 | rhs.1,
            self.2 | rhs.2,
            self.3 | rhs.3,
        )
    }
}


impl BitOrAssign for Nibble {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
        self.1 |= rhs.1;
        self.2 |= rhs.2;
        self.3 |= rhs.3;
    }
}


impl BitXor for Nibble {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self {
        Self (
            self.0 ^ rhs.0,
            self.1 ^ rhs.1,
            self.2 ^ rhs.2,
            self.3 ^ rhs.3,
        )
    }
}


impl BitXorAssign for Nibble {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
        self.1 ^= rhs.1;
        self.2 ^= rhs.2;
        self.3 ^= rhs.3;
    }
}


impl From<u8> for Nibble {
    fn from(v: u8) -> Self {
        Nibble::new(v, v >> 1, v >> 2, v >> 3)
    }
}


impl From<&Nibble> for u8 {
    fn from(v: &Nibble) -> Self {
        v.0      |
        v.1 << 1 |
        v.2 << 2 |
        v.3 << 3
    }
}


#[macro_export]
macro_rules! bb_and {
    ($v1: expr, $v2: expr) => {
        $v1 & $v2
    };

    ($v1: expr, $v2: expr, $v3: expr) => {
        $v1 & $v2 & $v3
    };

    ($v1: expr, $v2: expr, $v3: expr, $v4: expr) => {
        $v1 & $v2 & $v3 & $v4
    };
}


#[macro_export]
macro_rules! bb_or {
    ($v1: expr, $v2: expr) => {
        $v1 | $v2
    };

    ($v1: expr, $v2: expr, $v3: expr) => {
        $v1 | $v2 | $v3
    };

    ($v1: expr, $v2: expr, $v3: expr, $v4: expr) => {
        $v1 | $v2 | $v3 | $v4
    };

    ($v1: expr, $v2: expr, $v3: expr, $v4: expr, $v5: expr) => {
        $v1 | $v2 | $v3 | $v4 | $v5
    };
}


#[macro_export]
macro_rules! bb_xor {
    ($v1: expr, $v2: expr) => {
        $v1 ^ $v2
    };

    ($v1: expr, $v2: expr, $v3: expr) => {
        $v1 ^ $v2 ^ $v3
    };

    ($v1: expr, $v2: expr, $v3: expr, $v4: expr) => {
        $v1 ^ $v2 ^ $v3 ^ $v4
    };
}


#[macro_export]
macro_rules! bb_lsh {
    ($v: expr, $shift: expr) => {
        $v << $shift
    };
}


#[macro_export]
macro_rules! bb_rsh {
    ($v: expr, $shift: expr) => {
        $v >> $shift
    };
}


#[macro_export]
macro_rules! bb_add {
    ($v1: expr, $v2: expr) => {
        $v1 + $v2
    };

    ($v1: expr, $v2: expr, $v3: expr) => {
        $v1 + $v2 + $v3
    };

    ($v1: expr, $v2: expr, $v3: expr, $v4: expr) => {
        $v1 + $v2 + $v3 + $v4
    };
}


#[macro_export]
macro_rules! bb_and_01 {
    ($v: expr) => {
        bb_and!($v, 0x01)
    }
}


#[macro_export]
macro_rules! bb_and_0f {
    ($v: expr) => {
        bb_and!($v, 0x0F)
    }
}
