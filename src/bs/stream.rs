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

// --- The seven 5-input, 2-output stream S-boxes ---
//
// These are multi-level XOR/AND circuits synthesised from the reference
// 2-bit S-box tables with Berkeley ABC.

#[inline(always)]
fn sbox1<T: Bit>(a: T, b: T, c: T, d: T, e: T) -> (T, T) {
    let t0 = !(d ^ c);
    let t1 = b ^ t0;
    let t2 = !(e | t1);
    let t3 = d & !b;
    let t4 = e & !c;
    let t5 = t4 & !t3;
    let t6 = !(t5 | t2);
    let t7 = a & !t6;
    let t8 = c & !e;
    let t9 = !(e | d);
    let t10 = !(b | t9);
    let t11 = t10 & !t8;
    let t12 = t11 & t7;
    let t13 = !(t3 | t12);
    let t14 = !(a | t8);
    let t15 = !(t4 | t14);
    let t16 = d & !t15;
    let t17 = !(t16 | t13);
    let t18 = e & d;
    let t19 = c ^ t18;
    let t20 = a & !t19;
    let t21 = c & t18;
    let t22 = !(a | t9);
    let t23 = t22 & !t21;
    let t24 = b & !t23;
    let t25 = t24 & !t20;
    let t26 = !(b | t0);
    let t27 = c & !d;
    let t28 = !(t27 | t26);
    let t29 = t14 & !t28;
    let t30 = !(t29 | t25);
    let t31 = !t30 | t17;
    let t32 = b & t19;
    let t33 = !(t32 | t11);
    let t34 = t33 & !a;
    let t35 = t27 & t11;
    let t36 = !(t35 | t7);
    let t37 = !t36 | t34;
    (t31, t37)
}

#[inline(always)]
fn sbox2<T: Bit>(a: T, b: T, c: T, d: T, e: T) -> (T, T) {
    let t0 = d & !e;
    let t1 = e & c;
    let t2 = !(t1 | t0);
    let t3 = !(b | t2);
    let t4 = b & t2;
    let t5 = a & !t4;
    let t6 = t5 & !t3;
    let t7 = e & !b;
    let t8 = c & !t7;
    let t9 = d & !t8;
    let t10 = t9 & !t4;
    let t11 = t8 & !t0;
    let t12 = !(a | t11);
    let t13 = t12 & !t10;
    let t14 = t13 | t6;
    let t15 = e & !c;
    let t16 = !(d | t15);
    let t17 = e & d;
    let t18 = c & !a;
    let t19 = t18 ^ t17;
    let t20 = !(t19 | t16);
    let t21 = a & !t1;
    let t22 = !(t21 | t20);
    let t23 = a & !c;
    let t24 = t23 & !t17;
    let t25 = b & !t24;
    let t26 = t25 & !t22;
    let t27 = !(b | t20);
    let t28 = t27 | t26;
    (t14, t28)
}

#[inline(always)]
fn sbox3<T: Bit>(a: T, b: T, c: T, d: T, e: T) -> (T, T) {
    let t0 = d & !e;
    let t1 = e & c;
    let t2 = !(t1 | t0);
    let t3 = !(b ^ a);
    let t4 = t3 ^ t2;
    let t5 = d ^ b;
    let t6 = t5 & !t0;
    let t7 = e ^ c;
    let t8 = !(t7 | t6);
    let t9 = t7 & t6;
    let t10 = a & !t9;
    let t11 = t10 & !t8;
    let t12 = !(d | c);
    let t13 = e & t12;
    let t14 = !(d | b);
    let t15 = !(t7 | t14);
    let t16 = !(a | t15);
    let t17 = t16 & !t13;
    let t18 = t17 | t11;
    (t4, t18)
}

#[inline(always)]
fn sbox4<T: Bit>(a: T, b: T, c: T, d: T, e: T) -> (T, T) {
    let t0 = d & !c;
    let t1 = e & !t0;
    let t2 = a & t1;
    let t3 = d & !a;
    let t4 = t3 & !t1;
    let t5 = !(t4 | t2);
    let t6 = c ^ t5;
    let t7 = t6 & !b;
    let t8 = a & !c;
    let t9 = !(d | t8);
    let t10 = !(e | t9);
    let t11 = b & !t10;
    let t12 = e & t9;
    let t13 = !(t0 | t12);
    let t14 = t13 & t11;
    let t15 = e & !a;
    let t16 = t15 & t0;
    let t17 = !(t16 | t14);
    let t18 = !t17 | t7;
    let t19 = d ^ b;
    let t20 = c & t19;
    let t21 = b & !t20;
    let t22 = c & !b;
    let t23 = !(a | t22);
    let t24 = t23 & !t21;
    let t25 = !(d | c);
    let t26 = a & !t25;
    let t27 = t26 & !t20;
    let t28 = !(t27 | t24);
    let t29 = !(e | t28);
    let t30 = t19 & !a;
    let t31 = d & b;
    let t32 = a & t31;
    let t33 = c & !t32;
    let t34 = t33 & !t30;
    let t35 = !(t25 | t3);
    let t36 = t19 & !t35;
    let t37 = !(t36 | t34);
    let t38 = e & !t37;
    let t39 = t38 | t29;
    (t18, t39)
}

#[inline(always)]
fn sbox5<T: Bit>(a: T, b: T, c: T, d: T, e: T) -> (T, T) {
    let t0 = d ^ c;
    let t1 = e & !a;
    let t2 = !(t1 | t0);
    let t3 = e & t0;
    let t4 = b & !t3;
    let t5 = t4 & !t2;
    let t6 = b & !c;
    let t7 = e ^ t6;
    let t8 = !(d | t7);
    let t9 = c & !b;
    let t10 = d & !t9;
    let t11 = a & !t10;
    let t12 = t11 & !t8;
    let t13 = e & d;
    let t14 = !(t13 | t9);
    let t15 = e & c;
    let t16 = !(t15 | t14);
    let t17 = t16 & !a;
    let t18 = !(t17 | t12);
    let t19 = !t18 | t5;
    let t20 = !(e | t6);
    let t21 = !t0 & t20;
    let t22 = d & b;
    let t23 = t22 & !t15;
    let t24 = !(t9 | t23);
    let t25 = t24 & !t21;
    let t26 = !(a | t25);
    let t27 = t13 & !b;
    let t28 = c & !e;
    let t29 = b & !d;
    let t30 = !(t29 ^ t28);
    let t31 = a & t30;
    let t32 = t31 & !t27;
    let t33 = t32 | t26;
    (t19, t33)
}

#[inline(always)]
fn sbox6<T: Bit>(a: T, b: T, c: T, d: T, e: T) -> (T, T) {
    let t0 = c & !b;
    let t1 = e & t0;
    let t2 = d & a;
    let t3 = !(t2 | t1);
    let t4 = d & b;
    let t5 = t4 & !c;
    let t6 = e & !t5;
    let t7 = t6 & t3;
    let t8 = !(e | d);
    let t9 = !(t8 | t2);
    let t10 = t0 & !t9;
    let t11 = t4 & !e;
    let t12 = !(t11 | t10);
    let t13 = !t12 | t7;
    let t14 = !(e ^ c);
    let t15 = b & !t14;
    let t16 = !(d | a);
    let t17 = t3 & !t16;
    let t18 = t17 & !t15;
    let t19 = c & t16;
    let t20 = t19 & !t10;
    let t21 = t2 & !t0;
    let t22 = t21 & !t14;
    let t23 = !(t22 | t20);
    let t24 = !t23 | t18;
    (t13, t24)
}

#[inline(always)]
fn sbox7<T: Bit>(a: T, b: T, c: T, d: T, e: T) -> (T, T) {
    let t0 = !(d ^ a);
    let t1 = b & t0;
    let t2 = d & t1;
    let t3 = c & !t2;
    let t4 = e ^ t0;
    let t5 = t4 & t3;
    let t6 = !(b | t0);
    let t7 = e & !c;
    let t8 = t7 & !t1;
    let t9 = t8 & !t6;
    let t10 = a & !d;
    let t11 = b & !t10;
    let t12 = a & !b;
    let t13 = !(t12 | t11);
    let t14 = !(e | c);
    let t15 = t14 & !t13;
    let t16 = !(t15 | t9);
    let t17 = !t16 | t5;
    let t18 = e & a;
    let t19 = !(t18 | t14);
    let t20 = d & !t19;
    let t21 = !(e | t0);
    let t22 = e ^ c;
    let t23 = t22 & !a;
    let t24 = t23 & !t21;
    let t25 = !(t24 | t20);
    let t26 = !(b | t25);
    let t27 = t22 & t0;
    let t28 = d & !t18;
    let t29 = t28 & !t22;
    let t30 = b & !t29;
    let t31 = t30 & !t27;
    let t32 = t31 | t26;
    (t17, t32)
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
