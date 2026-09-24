//! 128-bit SSE2 bitslice word: 128 packets in parallel.
//!
//! `__m128i` cannot implement the std bit-op traits directly, so it is wrapped
//! in `W128`. SSE2 is part of the x86-64 baseline, so unlike AVX2 this backend
//! needs no runtime feature gate; it exists as a middle datapath between `u64`
//! (64 lanes) and AVX2 `W256` (256 lanes) — the widest vector every x86-64 CPU
//! is guaranteed to have, so it is the natural fallback when AVX2 is absent.

use core::{
    arch::x86_64::*,
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
pub struct W128(pub __m128i);

impl BitAnd for W128 {
    type Output = Self;
    #[inline(always)]
    fn bitand(self, r: Self) -> Self {
        unsafe { W128(_mm_and_si128(self.0, r.0)) }
    }
}

impl BitOr for W128 {
    type Output = Self;
    #[inline(always)]
    fn bitor(self, r: Self) -> Self {
        unsafe { W128(_mm_or_si128(self.0, r.0)) }
    }
}

impl BitXor for W128 {
    type Output = Self;
    #[inline(always)]
    fn bitxor(self, r: Self) -> Self {
        unsafe { W128(_mm_xor_si128(self.0, r.0)) }
    }
}

impl Not for W128 {
    type Output = Self;
    #[inline(always)]
    fn not(self) -> Self {
        // No NOT intrinsic: xor with all-ones.
        unsafe { W128(_mm_xor_si128(self.0, _mm_set1_epi8(-1i8))) }
    }
}

impl Word for W128 {
    const LANES: usize = 128;

    #[inline(always)]
    fn zero() -> Self {
        unsafe { W128(_mm_setzero_si128()) }
    }

    #[inline(always)]
    fn ones() -> Self {
        unsafe { W128(_mm_set1_epi8(-1i8)) }
    }

    #[inline(always)]
    fn gather_bitplanes(col: &[u8]) -> [W128; 8] {
        // Split the (up to) 128 lanes into two 64-lane limbs and reuse the u64
        // SWAR transpose on each; lane p lives in limb p/64, u64-bit p%64.
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
            planes[bit] = W128(unsafe { _mm_loadu_si128(limbs[bit].as_ptr() as *const __m128i) });
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
        // Byte-interleave the planes so each u64 holds byte j of planes 0..8, then run the
        // `transpose8` stages on two u64 at once.
        unsafe {
            let p = planes.map(|w| w.0);
            let a = [
                _mm_unpacklo_epi8(p[0], p[1]),
                _mm_unpackhi_epi8(p[0], p[1]),
                _mm_unpacklo_epi8(p[2], p[3]),
                _mm_unpackhi_epi8(p[2], p[3]),
                _mm_unpacklo_epi8(p[4], p[5]),
                _mm_unpackhi_epi8(p[4], p[5]),
                _mm_unpacklo_epi8(p[6], p[7]),
                _mm_unpackhi_epi8(p[6], p[7]),
            ];
            let mut b = [_mm_setzero_si128(); 8];
            for k in 0 .. 2 {
                b[4 * k] = _mm_unpacklo_epi16(a[k], a[2 + k]);
                b[4 * k + 1] = _mm_unpackhi_epi16(a[k], a[2 + k]);
                b[4 * k + 2] = _mm_unpacklo_epi16(a[4 + k], a[6 + k]);
                b[4 * k + 3] = _mm_unpackhi_epi16(a[4 + k], a[6 + k]);
            }
            let dst = col.as_mut_ptr() as *mut __m128i;
            for k in 0 .. 4 {
                let i = k / 2 * 4 + k % 2; // pairs b[i], b[i + 2]
                let lo = _mm_unpacklo_epi32(b[i], b[i + 2]);
                let hi = _mm_unpackhi_epi32(b[i], b[i + 2]);
                _mm_storeu_si128(dst.add(2 * k), transpose8x2(lo));
                _mm_storeu_si128(dst.add(2 * k + 1), transpose8x2(hi));
            }
        }
    }
}

/// [`crate::bs::word::transpose8`] on each u64 of `x`.
#[inline(always)]
unsafe fn transpose8x2(mut x: __m128i) -> __m128i {
    unsafe {
        let mut t;
        t = _mm_and_si128(
            _mm_xor_si128(x, _mm_srli_epi64::<7>(x)),
            _mm_set1_epi64x(0x00AA_00AA_00AA_00AA),
        );
        x = _mm_xor_si128(x, _mm_xor_si128(t, _mm_slli_epi64::<7>(t)));
        t = _mm_and_si128(
            _mm_xor_si128(x, _mm_srli_epi64::<14>(x)),
            _mm_set1_epi64x(0x0000_CCCC_0000_CCCC),
        );
        x = _mm_xor_si128(x, _mm_xor_si128(t, _mm_slli_epi64::<14>(t)));
        t = _mm_and_si128(
            _mm_xor_si128(x, _mm_srli_epi64::<28>(x)),
            _mm_set1_epi64x(0x0000_0000_F0F0_F0F0),
        );
        _mm_xor_si128(x, _mm_xor_si128(t, _mm_slli_epi64::<28>(t)))
    }
}
