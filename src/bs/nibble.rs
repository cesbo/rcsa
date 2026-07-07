//! Bitslice nibble: four [`Word`]s, `b0` = LSB. Mirrors the scalar `Nibble`.

use core::ops::BitXor;

use crate::bs::word::Word;

#[derive(Copy, Clone)]
pub struct Nibble<W>(pub W, pub W, pub W, pub W);

impl<W: Word> Nibble<W> {
    #[inline(always)]
    pub fn zero() -> Self {
        Nibble(W::zero(), W::zero(), W::zero(), W::zero())
    }
}

impl<W: Word> BitXor for Nibble<W> {
    type Output = Self;
    #[inline(always)]
    fn bitxor(self, r: Self) -> Self {
        Nibble(self.0 ^ r.0, self.1 ^ r.1, self.2 ^ r.2, self.3 ^ r.3)
    }
}
