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
    scatter64,
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
            planes[bit] =
                W128(unsafe { _mm_loadu_si128(limbs[bit].as_ptr() as *const __m128i) });
        }
        planes
    }

    #[inline(always)]
    fn scatter_bitplanes(planes: &[W128; 8], col: &mut [u8]) {
        let n = col.len();
        let mut limbs = [[0u64; 2]; 8];
        for bit in 0 .. 8 {
            unsafe {
                _mm_storeu_si128(limbs[bit].as_mut_ptr() as *mut __m128i, planes[bit].0);
            }
        }
        let mut l = 0;
        while l * 64 < n {
            let end = core::cmp::min(l * 64 + 64, n);
            let mut sub = [0u64; 8];
            for bit in 0 .. 8 {
                sub[bit] = limbs[bit][l];
            }
            scatter64(&sub, &mut col[l * 64 .. end]);
            l += 1;
        }
    }
}
