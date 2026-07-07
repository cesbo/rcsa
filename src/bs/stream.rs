//! Bitslice port of the CSA stream cipher (`Csa::stream_cypher*`, src/csa.rs).
//!
//! The seven stream S-boxes are the exact boolean formulas from the scalar
//! `a_group_xor`, extracted into standalone functions so they can be verified
//! against the reference tables (see the tests). They are generic over the raw
//! `Copy + BitAnd + BitOr + BitXor + Not` bound (not `Word`) so the tests can
//! instantiate them with `u8` (each logical bit broadcast to 0x00/0xFF).

use core::ops::{
    BitAnd,
    BitOr,
    BitXor,
    Not,
};

use crate::bs::{
    nibble::Nibble,
    word::{
        Block,
        Word,
    },
};

/// The bound shared by `block_sbox` and the stream S-boxes.
trait Bit:
    Copy + BitAnd<Output = Self> + BitOr<Output = Self> + BitXor<Output = Self> + Not<Output = Self>
{
}
impl<T> Bit for T where
    T: Copy + BitAnd<Output = T> + BitOr<Output = T> + BitXor<Output = T> + Not<Output = T>
{
}

#[inline(always)]
fn sum_bit<W: Word>(z: W, e: W, carry: W, q: W) -> (W, W) {
    (e ^ (q & (z ^ carry)), (z & e) | ((z ^ e) & carry))
}

#[inline(always)]
fn sum_nibble<W: Word>(z: Nibble<W>, e: Nibble<W>, r: W, q: W) -> (Nibble<W>, W) {
    let carry = r;
    let (r0, carry) = sum_bit(z.0, e.0, carry, q);
    let (r1, carry) = sum_bit(z.1, e.1, carry, q);
    let (r2, carry) = sum_bit(z.2, e.2, carry, q);
    let (r3, carry) = sum_bit(z.3, e.3, carry, q);
    (Nibble(r0, r1, r2, r3), r ^ (q & (carry ^ r)))
}

#[inline(always)]
fn rotate_nibble<W: Word>(n: Nibble<W>, p: W) -> Nibble<W> {
    Nibble(
        n.0 ^ (p & (n.3 ^ n.0)),
        n.1 ^ (p & (n.0 ^ n.1)),
        n.2 ^ (p & (n.1 ^ n.2)),
        n.3 ^ (p & (n.2 ^ n.3)),
    )
}

// --- The seven 5-input stream S-boxes (verbatim from scalar a_group_xor) ---

#[inline(always)]
fn sbox1<T: Bit>(a: T, b: T, c: T, d: T, e: T) -> (T, T) {
    let s1a = (!a & b & !d & !e)
        | (!a & c & !d & e)
        | (a & !c & e & !(b ^ d))
        | (!b & d & !e)
        | (b & c & (a ^ e))
        | (b & c & !d)
        | (!b & d & !(a ^ c));
    let s1b = (!a & !b & !d & !e)
        | (a & !b & !c & d & !e)
        | (a & b & !c & e)
        | (a & !c & !d & e)
        | (b & c & d & (a ^ e))
        | (!d & (b ^ c))
        | (!a & !e & (b ^ c));
    (s1a, s1b)
}

#[inline(always)]
fn sbox2<T: Bit>(a: T, b: T, c: T, d: T, e: T) -> (T, T) {
    let s2a = (!a & !c & !d)
        | (!a & c & d & !e)
        | (a & b & c & e)
        | (a & b & d & !e)
        | (!c & e & (a ^ b))
        | (!b & !d & (a ^ e));
    let s2b = (!a & b & !c & (d ^ e))
        | (!a & b & c & d & e)
        | (a & !b & d & e)
        | (a & !c & d & e)
        | (!b & !c & d & e)
        | (!b & c & !d)
        | (!b & !d & !e)
        | (c & !e & !(a ^ b));
    (s2a, s2b)
}

#[inline(always)]
fn sbox3<T: Bit>(a: T, b: T, c: T, d: T, e: T) -> (T, T) {
    let s3a = (!e & (a ^ b ^ d)) | (e & (a ^ b ^ c));
    let s3b = (!a & !b & !d & !e)
        | (!a & !c & d & e)
        | (!a & c & !e)
        | (a & b & c & !d & e)
        | (a & !c & !d & (b ^ e))
        | (!b & c & !e)
        | (b & !c & d & e)
        | (c & d & !e)
        | (!b & c & !(a ^ d));
    (s3a, s3b)
}

#[inline(always)]
fn sbox4<T: Bit>(a: T, b: T, c: T, d: T, e: T) -> (T, T) {
    let s4a = (!a & !b & c & d & !e)
        | (!a & !c & !(d ^ e))
        | (a & !b & c & e)
        | (a & b & !c & !d & e)
        | (b & c & !d & !e)
        | (d & e & !(b ^ c))
        | (!b & !c & (a ^ e));
    let s4b = (!a & !b & !c & !e)
        | (!a & b & c & !d & !e)
        | (!a & c & d & e)
        | (a & !b & c & !d)
        | (a & b & (d ^ e))
        | (!b & !c & d & !e)
        | (!b & c & e)
        | (b & !c & !d & e)
        | (!a & !b & !c & d);
    (s4a, s4b)
}

#[inline(always)]
fn sbox5<T: Bit>(a: T, b: T, c: T, d: T, e: T) -> (T, T) {
    let s5a = (!a & b & d & e)
        | (!a & !c & d & e)
        | (!a & c & !d & !e)
        | (a & !b & !d & e)
        | (a & c & (b ^ d))
        | (b & !c & (a ^ e))
        | (b & !c & d & !e)
        | (!a & !b & c & !e);
    let s5b = (!a & c & d & !e)
        | (a & !b & !c & !e)
        | (a & b & c & !d & !e)
        | (a & e & !(b ^ d))
        | (!b & !c & !d & !e)
        | (b & !c & d)
        | (!a & !b & c);
    (s5a, s5b)
}

#[inline(always)]
fn sbox6<T: Bit>(a: T, b: T, c: T, d: T, e: T) -> (T, T) {
    let s6a =
        (!b & c & !d & !e) | (b & (d ^ e)) | (!c & !d & e) | (c & d & (a ^ b)) | (!a & !b & !c & e);
    let s6b = (!a & b & c & !d)
        | (!a & b & c & e)
        | (!a & c & !d & e)
        | (a & b & c & d & !e)
        | (a & !c & d & e)
        | (!b & !e & (a ^ d))
        | (b & c & !d & e)
        | (!c & !e & (a ^ d))
        | (!b & !c & (a ^ d));
    (s6a, s6b)
}

/// Returns `(q, p)` (matching scalar `self.q`, `self.p`).
#[inline(always)]
fn sbox7<T: Bit>(a: T, b: T, c: T, d: T, e: T) -> (T, T) {
    let q = (!a & c & !(d ^ e))
        | (a & !b & d & !e)
        | (a & b & !d & e)
        | (a & c & !d & e)
        | (b & !c & d & !e)
        | (!c & d & (a ^ b))
        | (!c & !e & (a ^ b))
        | (!a & !b & !c & !d & e);
    let p = (!a & c & !e & !(b ^ d))
        | (a & b & !d)
        | (!b & !c & d)
        | (b & !d & !(c ^ e))
        | (d & e & !(a ^ c))
        | (!a & !b & !c & e);
    (q, p)
}

/// Stream-cipher registers, mirroring the stream fields of the scalar `Csa`.
pub struct StreamState<W> {
    a: [Nibble<W>; 42],
    b: [Nibble<W>; 42],
    x: Nibble<W>,
    y: Nibble<W>,
    z: Nibble<W>,
    d: Nibble<W>,
    e: Nibble<W>,
    f: Nibble<W>,
    r: W,
    p: W,
    q: W,
}

impl<W: Word> StreamState<W> {
    #[inline(always)]
    pub fn new() -> Self {
        StreamState {
            a: [Nibble::zero(); 42],
            b: [Nibble::zero(); 42],
            x: Nibble::zero(),
            y: Nibble::zero(),
            z: Nibble::zero(),
            d: Nibble::zero(),
            e: Nibble::zero(),
            f: Nibble::zero(),
            r: W::zero(),
            p: W::zero(),
            q: W::zero(),
        }
    }

    /// Port of `Csa::stream_init`.
    #[inline(always)]
    pub fn stream_init(&mut self, ccw: &[Nibble<W>; 16]) {
        self.a[32 .. 40].copy_from_slice(&ccw[0 .. 8]);
        self.b[32 .. 40].copy_from_slice(&ccw[8 .. 16]);
        self.a[40] = Nibble::zero();
        self.a[41] = Nibble::zero();
        self.b[40] = Nibble::zero();
        self.b[41] = Nibble::zero();
        self.x = Nibble::zero();
        self.y = Nibble::zero();
        self.z = Nibble::zero();
        self.d = Nibble::zero();
        self.e = Nibble::zero();
        self.f = Nibble::zero();
        self.r = W::zero();
        self.p = W::zero();
        self.q = W::zero();
    }

    /// Port of `Csa::b_group_xor`.
    #[inline(always)]
    fn b_group_xor(&mut self, skip: usize) {
        let tmp = Nibble(
            self.b[skip + 9].2 ^ self.b[skip + 6].3 ^ self.b[skip + 3].1 ^ self.b[skip + 8].0,
            self.b[skip + 5].3 ^ self.b[skip + 8].2 ^ self.b[skip + 4].0 ^ self.b[skip + 5].1,
            self.b[skip + 6].0 ^ self.b[skip + 8].1 ^ self.b[skip + 3].3 ^ self.b[skip + 4].2,
            self.b[skip + 3].0 ^ self.b[skip + 6].1 ^ self.b[skip + 7].2 ^ self.b[skip + 9].3,
        );
        self.d = self.e ^ self.z ^ tmp;

        let (f, r) = sum_nibble(self.z, self.e, self.r, self.q);
        self.e = self.f;
        self.f = f;
        self.r = r;
    }

    /// Port of `Csa::a_group_xor` (the seven S-boxes set X, Y, Z, p, q).
    #[inline(always)]
    fn a_group_xor(&mut self, skip: usize) {
        let (s1a, s1b) = sbox1(
            self.a[skip + 4].0,
            self.a[skip + 1].2,
            self.a[skip + 6].1,
            self.a[skip + 7].3,
            self.a[skip + 9].0,
        );
        let (s2a, s2b) = sbox2(
            self.a[skip + 2].1,
            self.a[skip + 3].2,
            self.a[skip + 6].3,
            self.a[skip + 7].0,
            self.a[skip + 9].1,
        );
        let (s3a, s3b) = sbox3(
            self.a[skip + 1].3,
            self.a[skip + 2].0,
            self.a[skip + 5].1,
            self.a[skip + 5].3,
            self.a[skip + 6].2,
        );
        let (s4a, s4b) = sbox4(
            self.a[skip + 3].3,
            self.a[skip + 1].1,
            self.a[skip + 2].3,
            self.a[skip + 4].2,
            self.a[skip + 8].0,
        );
        let (s5a, s5b) = sbox5(
            self.a[skip + 5].2,
            self.a[skip + 4].3,
            self.a[skip + 6].0,
            self.a[skip + 8].1,
            self.a[skip + 9].2,
        );
        let (s6a, s6b) = sbox6(
            self.a[skip + 3].1,
            self.a[skip + 4].1,
            self.a[skip + 5].0,
            self.a[skip + 7].2,
            self.a[skip + 9].3,
        );

        self.x = Nibble(s1b, s2b, s3a, s4a);
        self.y = Nibble(s3b, s4b, s5a, s6a);
        self.z = Nibble(s5b, s6b, s1a, s2a);

        let (q, p) = sbox7(
            self.a[skip + 2].2,
            self.a[skip + 3].0,
            self.a[skip + 7].1,
            self.a[skip + 8].2,
            self.a[skip + 8].3,
        );
        self.q = q;
        self.p = p;
    }

    /// Port of `Csa::stream_cypher_init`. `block` is the first 8-byte block in
    /// bitslice form; its high/low nibbles seed the registers.
    #[inline(always)]
    pub fn stream_cypher_init(&mut self, block: &Block<W>) {
        for i in 0 .. 8 {
            let high = Nibble(block[i][4], block[i][5], block[i][6], block[i][7]);
            let low = Nibble(block[i][0], block[i][1], block[i][2], block[i][3]);
            for j in 0 .. 4 {
                let skip = 31 - i * 4 - j;
                // scalar: tmp_a = high nibble when j even, low when j odd;
                //         tmp_b = low  nibble when j even, high when j odd.
                let (ta, tb) = if j & 1 == 0 { (high, low) } else { (low, high) };
                self.a[skip] = self.a[skip + 10] ^ self.x ^ self.d ^ ta;
                self.b[skip] = self.b[skip + 10] ^ self.y ^ self.b[skip + 7] ^ tb;
                self.b[skip] = rotate_nibble(self.b[skip], self.p);
                self.b_group_xor(skip);
                self.a_group_xor(skip);
            }
        }
        self.a.copy_within(0 .. 10, 32);
        self.b.copy_within(0 .. 10, 32);
    }

    /// Port of `Csa::stream_cypher`. Returns 8 bytes of keystream in bitslice
    /// form (byte-major, LSB-first).
    #[inline(always)]
    pub fn stream_cypher(&mut self) -> Block<W> {
        let mut ks = [[W::zero(); 8]; 8];
        for i in 0 .. 8 {
            for j in 0 .. 4 {
                let skip = 31 - i * 4 - j;
                self.a[skip] = self.a[skip + 10] ^ self.x;
                self.b[skip] = self.b[skip + 10] ^ self.y ^ self.b[skip + 7];
                self.b[skip] = rotate_nibble(self.b[skip], self.p);
                self.b_group_xor(skip);
                self.a_group_xor(skip);

                // scalar: cb = (cb << 2) | (((d.2^d.3)<<1) | (d.0^d.1))
                //   => iteration j fills byte-bit positions 2*(3-j) and +1.
                let lo = self.d.0 ^ self.d.1;
                let hi = self.d.2 ^ self.d.3;
                let pos = 2 * (3 - j);
                ks[i][pos] = lo;
                ks[i][pos + 1] = hi;
            }
        }
        self.a.copy_within(0 .. 10, 32);
        self.b.copy_within(0 .. 10, 32);
        ks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference 2-bit S-box tables (from origin/csa.c; also in csa.rs comments).
    // Index = a<<4 | b<<3 | c<<2 | d<<1 | e ; value: bit0 = sNa, bit1 = sNb.
    const SBOX1: [u8; 32] = [
        2, 0, 1, 1, 2, 3, 3, 0, 3, 2, 2, 0, 1, 1, 0, 3, 0, 3, 3, 0, 2, 2, 1, 1, 2, 2, 0, 3, 1, 1,
        3, 0,
    ];
    const SBOX2: [u8; 32] = [
        3, 1, 0, 2, 2, 3, 3, 0, 1, 3, 2, 1, 0, 0, 1, 2, 3, 1, 0, 3, 3, 2, 0, 2, 0, 0, 1, 2, 2, 1,
        3, 1,
    ];
    const SBOX3: [u8; 32] = [
        2, 0, 1, 2, 2, 3, 3, 1, 1, 1, 0, 3, 3, 0, 2, 0, 1, 3, 0, 1, 3, 0, 2, 2, 2, 0, 1, 2, 0, 3,
        3, 1,
    ];
    const SBOX4: [u8; 32] = [
        3, 1, 2, 3, 0, 2, 1, 2, 1, 2, 0, 1, 3, 0, 0, 3, 1, 0, 3, 1, 2, 3, 0, 3, 0, 3, 2, 0, 1, 2,
        2, 1,
    ];
    const SBOX5: [u8; 32] = [
        2, 0, 0, 1, 3, 2, 3, 2, 0, 1, 3, 3, 1, 0, 2, 1, 2, 3, 2, 0, 0, 3, 1, 1, 1, 0, 3, 2, 3, 1,
        0, 2,
    ];
    const SBOX6: [u8; 32] = [
        0, 1, 2, 3, 1, 2, 2, 0, 0, 1, 3, 0, 2, 3, 1, 3, 2, 3, 0, 2, 3, 0, 1, 1, 2, 1, 1, 2, 0, 3,
        3, 0,
    ];
    // sbox7: value bit0 = q, bit1 = p.
    const SBOX7: [u8; 32] = [
        0, 3, 2, 2, 3, 0, 0, 1, 3, 0, 1, 3, 1, 2, 2, 1, 1, 0, 3, 3, 0, 1, 1, 2, 2, 3, 1, 0, 2, 3,
        0, 2,
    ];

    fn bit(v: u8) -> u8 {
        if v & 1 == 1 { 0xFF } else { 0x00 }
    }

    fn check(f: fn(u8, u8, u8, u8, u8) -> (u8, u8), table: &[u8; 32]) {
        for idx in 0 .. 32u8 {
            let a = bit(idx >> 4);
            let b = bit(idx >> 3);
            let c = bit(idx >> 2);
            let d = bit(idx >> 1);
            let e = bit(idx);
            let (lo, hi) = f(a, b, c, d, e);
            assert!(lo == 0x00 || lo == 0xFF);
            assert!(hi == 0x00 || hi == 0xFF);
            let want_lo = table[idx as usize] & 1 == 1;
            let want_hi = (table[idx as usize] >> 1) & 1 == 1;
            assert_eq!(lo == 0xFF, want_lo, "sbox lo mismatch at idx {idx}");
            assert_eq!(hi == 0xFF, want_hi, "sbox hi mismatch at idx {idx}");
        }
    }

    #[test]
    fn stream_sboxes_match_reference_tables() {
        check(sbox1, &SBOX1);
        check(sbox2, &SBOX2);
        check(sbox3, &SBOX3);
        check(sbox4, &SBOX4);
        check(sbox5, &SBOX5);
        check(sbox6, &SBOX6);
        check(sbox7, &SBOX7);
    }
}
