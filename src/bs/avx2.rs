//! 256-bit AVX2 bitslice word: 256 packets in parallel.
//!
//! `__m256i` cannot implement the std bit-op traits directly, so it is wrapped
//! in `W256`. The intrinsics are only emitted where the whole call tree is
//! inlined into a `#[target_feature(enable = "avx2")]` root (see `batch.rs`),
//! and that root is reached only behind `is_x86_feature_detected!("avx2")`.

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
pub struct W256(pub __m256i);

impl BitAnd for W256 {
    type Output = Self;
    #[inline(always)]
    fn bitand(self, r: Self) -> Self {
        unsafe { W256(_mm256_and_si256(self.0, r.0)) }
    }
}

impl BitOr for W256 {
    type Output = Self;
    #[inline(always)]
    fn bitor(self, r: Self) -> Self {
        unsafe { W256(_mm256_or_si256(self.0, r.0)) }
    }
}

impl BitXor for W256 {
    type Output = Self;
    #[inline(always)]
    fn bitxor(self, r: Self) -> Self {
        unsafe { W256(_mm256_xor_si256(self.0, r.0)) }
    }
}

impl Not for W256 {
    type Output = Self;
    #[inline(always)]
    fn not(self) -> Self {
        // No NOT intrinsic: xor with all-ones.
        unsafe { W256(_mm256_xor_si256(self.0, _mm256_set1_epi8(-1i8))) }
    }
}

impl Word for W256 {
    const LANES: usize = 256;

    #[inline(always)]
    fn zero() -> Self {
        unsafe { W256(_mm256_setzero_si256()) }
    }

    #[inline(always)]
    fn ones() -> Self {
        unsafe { W256(_mm256_set1_epi8(-1i8)) }
    }

    #[inline(always)]
    fn gather_bitplanes(col: &[u8]) -> [W256; 8] {
        // Split the (up to) 256 lanes into four 64-lane limbs and reuse the u64
        // SWAR transpose on each; lane p lives in limb p/64, u64-bit p%64.
        let n = col.len();
        let mut limbs = [[0u64; 4]; 8];
        let mut l = 0;
        while l * 64 < n {
            let end = core::cmp::min(l * 64 + 64, n);
            let sub = gather64(&col[l * 64 .. end]);
            for bit in 0 .. 8 {
                limbs[bit][l] = sub[bit];
            }
            l += 1;
        }
        let mut planes = [W256::zero(); 8];
        for bit in 0 .. 8 {
            planes[bit] =
                W256(unsafe { _mm256_loadu_si256(limbs[bit].as_ptr() as *const __m256i) });
        }
        planes
    }

    #[inline(always)]
    fn scatter_bitplanes(planes: &[W256; 8], col: &mut [u8]) {
        let n = col.len();
        let mut limbs = [[0u64; 4]; 8];
        for bit in 0 .. 8 {
            unsafe {
                _mm256_storeu_si256(limbs[bit].as_mut_ptr() as *mut __m256i, planes[bit].0);
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
