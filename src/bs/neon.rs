//! 128-bit NEON bitslice word: 128 packets in parallel. NEON is part of the aarch64
//! baseline, so this backend needs no runtime feature gate.

use core::{
    arch::aarch64::*,
    ops::{
        BitAnd,
        BitOr,
        BitXor,
        Not,
    },
};

use crate::bs::word::{
    Word,
    gather64,
};

#[derive(Copy, Clone)]
pub struct W128(pub uint8x16_t);

impl BitAnd for W128 {
    type Output = Self;
    #[inline(always)]
    fn bitand(self, r: Self) -> Self {
        unsafe { W128(vandq_u8(self.0, r.0)) }
    }
}

impl BitOr for W128 {
    type Output = Self;
    #[inline(always)]
    fn bitor(self, r: Self) -> Self {
        unsafe { W128(vorrq_u8(self.0, r.0)) }
    }
}

impl BitXor for W128 {
    type Output = Self;
    #[inline(always)]
    fn bitxor(self, r: Self) -> Self {
        unsafe { W128(veorq_u8(self.0, r.0)) }
    }
}

impl Not for W128 {
    type Output = Self;
    #[inline(always)]
    fn not(self) -> Self {
        unsafe { W128(vmvnq_u8(self.0)) }
    }
}

impl Word for W128 {
    const LANES: usize = 128;

    #[inline(always)]
    fn zero() -> Self {
        unsafe { W128(vdupq_n_u8(0)) }
    }

    #[inline(always)]
    fn ones() -> Self {
        unsafe { W128(vdupq_n_u8(0xFF)) }
    }

    #[inline(always)]
    fn gather_bitplanes(col: &[u8]) -> [W128; 8] {
        // Two 64-lane limbs through the u64 SWAR transpose; lane p lives in limb p/64,
        // u64-bit p%64.
        let n = col.len();
        let mut limbs = [[0u64; 2]; 8];
        let mut l = 0;
        while l * 64 < n {
            let end = core::cmp::min(l * 64 + 64, n);
            let sub = gather64(&col[l * 64 .. end]);
            for bit in 0 .. 8 {
                limbs[bit][l] = sub[bit];
            }
            l += 1;
        }
        let mut planes = [W128::zero(); 8];
        for bit in 0 .. 8 {
            planes[bit] = W128(unsafe { vreinterpretq_u8_u64(vld1q_u64(limbs[bit].as_ptr())) });
        }
        planes
    }

    #[inline(always)]
    fn scatter_bitplanes(planes: &[W128; 8], col: &mut [u8]) {
        if col.len() < Self::LANES {
            let mut full = [0u8; 128];
            Self::scatter_bitplanes(planes, &mut full);
            let n = col.len();
            col.copy_from_slice(&full[.. n]);
            return;
        }
        // Same interleave as the SSE2 backend (zip1/zip2 = unpacklo/unpackhi): each u64
        // ends up holding byte j of planes 0..8, then `transpose8` runs on two u64 at once.
        unsafe {
            let p = planes.map(|w| w.0);
            let a = [
                vzip1q_u8(p[0], p[1]),
                vzip2q_u8(p[0], p[1]),
                vzip1q_u8(p[2], p[3]),
                vzip2q_u8(p[2], p[3]),
                vzip1q_u8(p[4], p[5]),
                vzip2q_u8(p[4], p[5]),
                vzip1q_u8(p[6], p[7]),
                vzip2q_u8(p[6], p[7]),
            ]
            .map(|v| vreinterpretq_u16_u8(v));
            let mut b = [vdupq_n_u32(0); 8];
            for k in 0 .. 2 {
                b[4 * k] = vreinterpretq_u32_u16(vzip1q_u16(a[k], a[2 + k]));
                b[4 * k + 1] = vreinterpretq_u32_u16(vzip2q_u16(a[k], a[2 + k]));
                b[4 * k + 2] = vreinterpretq_u32_u16(vzip1q_u16(a[4 + k], a[6 + k]));
                b[4 * k + 3] = vreinterpretq_u32_u16(vzip2q_u16(a[4 + k], a[6 + k]));
            }
            let dst = col.as_mut_ptr() as *mut u64;
            for k in 0 .. 4 {
                let i = k / 2 * 4 + k % 2; // pairs b[i], b[i + 2]
                let lo = vreinterpretq_u64_u32(vzip1q_u32(b[i], b[i + 2]));
                let hi = vreinterpretq_u64_u32(vzip2q_u32(b[i], b[i + 2]));
                vst1q_u64(dst.add(4 * k), transpose8x2(lo));
                vst1q_u64(dst.add(4 * k + 2), transpose8x2(hi));
            }
        }
    }
}

/// [`crate::bs::word::transpose8`] on each u64 of `x`.
#[inline(always)]
unsafe fn transpose8x2(mut x: uint64x2_t) -> uint64x2_t {
    unsafe {
        let mut t;
        t = vandq_u64(
            veorq_u64(x, vshrq_n_u64::<7>(x)),
            vdupq_n_u64(0x00AA_00AA_00AA_00AA),
        );
        x = veorq_u64(x, veorq_u64(t, vshlq_n_u64::<7>(t)));
        t = vandq_u64(
            veorq_u64(x, vshrq_n_u64::<14>(x)),
            vdupq_n_u64(0x0000_CCCC_0000_CCCC),
        );
        x = veorq_u64(x, veorq_u64(t, vshlq_n_u64::<14>(t)));
        t = vandq_u64(
            veorq_u64(x, vshrq_n_u64::<28>(x)),
            vdupq_n_u64(0x0000_0000_F0F0_F0F0),
        );
        veorq_u64(x, veorq_u64(t, vshlq_n_u64::<28>(t)))
    }
}
