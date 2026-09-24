//! Bitslice word abstraction and the packet <-> bitslice transpose.
//!
//! A [`Word`] is one machine word holding `LANES` independent packets, one per
//! lane. A logical bit is stored per lane as all-zeros (false) or all-ones
//! (true), so `!` is a correct per-lane NOT and the generated `block_sbox`
//! circuit (generic over `Copy + BitAnd + BitOr + BitXor + Not`) works unchanged.

use core::ops::{
    BitAnd,
    BitOr,
    BitXor,
    Not,
};

/// MPEG-TS packet size.
pub const PKT: usize = 188;
/// Unscrambled TS header size (copied verbatim, never touched here).
pub const HDR: usize = 4;
/// CSA cipher block size.
pub const BLK: usize = 8;
/// Scrambled payload blocks per packet (184 / 8).
pub const BLOCKS: usize = 23;
/// Largest supported batch width (AVX2), used to size transpose scratch.
pub const MAX_LANES: usize = 256;

/// One bitslice machine word: `LANES` packets processed in lockstep.
pub trait Word:
    Copy + BitAnd<Output = Self> + BitOr<Output = Self> + BitXor<Output = Self> + Not<Output = Self>
{
    /// Packets processed in parallel per word.
    const LANES: usize;
    /// All-zero word (every lane false).
    fn zero() -> Self;
    /// All-one word (every lane true); equals `!zero()`.
    fn ones() -> Self;
    /// Broadcast one logical bit to every lane.
    #[inline(always)]
    fn splat(bit: bool) -> Self {
        if bit { Self::ones() } else { Self::zero() }
    }

    /// Transpose one byte-position of `col.len()` packets (`col[p]` is packet
    /// `p`'s byte) into 8 bit-planes: `planes[bit]` lane `p` = bit `bit` of
    /// `col[p]`. `col.len()` must be `<= LANES`; higher lanes stay zero.
    fn gather_bitplanes(col: &[u8]) -> [Self; 8];
    /// Inverse of [`gather_bitplanes`]: write `col.len()` packet bytes back.
    fn scatter_bitplanes(planes: &[Self; 8], col: &mut [u8]);
}

/// Transpose an 8x8 bit matrix packed row-major in a `u64` (byte `k` = row `k`,
/// bit `b` = column `b`): result bit `8*b + k` = input bit `8*k + b`. Involution.
#[inline(always)]
pub(crate) fn transpose8(mut x: u64) -> u64 {
    let mut t;
    t = (x ^ (x >> 7)) & 0x00AA_00AA_00AA_00AA;
    x ^= t ^ (t << 7);
    t = (x ^ (x >> 14)) & 0x0000_CCCC_0000_CCCC;
    x ^= t ^ (t << 14);
    t = (x ^ (x >> 28)) & 0x0000_0000_F0F0_F0F0;
    x ^= t ^ (t << 28);
    x
}

/// Gather up to 64 packet bytes into 8 `u64` bit-planes via `transpose8`.
#[inline(always)]
pub(crate) fn gather64(col: &[u8]) -> [u64; 8] {
    debug_assert!(col.len() <= 64);
    let mut planes = [0u64; 8];
    let n = col.len();
    let mut j = 0;
    while j * 8 < n {
        let take = core::cmp::min(8, n - j * 8);
        let mut m = 0u64;
        for k in 0 .. take {
            m |= (col[j * 8 + k] as u64) << (8 * k);
        }
        let b = transpose8(m).to_le_bytes();
        for bit in 0 .. 8 {
            planes[bit] |= (b[bit] as u64) << (8 * j);
        }
        j += 1;
    }
    planes
}

/// Inverse of [`gather64`]: scatter 8 `u64` bit-planes back to `col.len()` bytes.
#[inline(always)]
pub(crate) fn scatter64(planes: &[u64; 8], col: &mut [u8]) {
    debug_assert!(col.len() <= 64);
    let n = col.len();
    let mut j = 0;
    while j * 8 < n {
        let mut mt = 0u64;
        for bit in 0 .. 8 {
            mt |= ((planes[bit] >> (8 * j)) & 0xff) << (8 * bit);
        }
        let m = transpose8(mt).to_le_bytes();
        let take = core::cmp::min(8, n - j * 8);
        col[j * 8 .. j * 8 + take].copy_from_slice(&m[.. take]);
        j += 1;
    }
}

impl Word for u64 {
    const LANES: usize = 64;
    #[inline(always)]
    fn zero() -> Self {
        0
    }
    #[inline(always)]
    fn ones() -> Self {
        u64::MAX
    }
    #[inline(always)]
    fn gather_bitplanes(col: &[u8]) -> [u64; 8] {
        gather64(col)
    }
    #[inline(always)]
    fn scatter_bitplanes(planes: &[u64; 8], col: &mut [u8]) {
        scatter64(planes, col);
    }
}

/// One 8-byte cipher block in bitslice form: `[byte][bit]`, LSB-first.
pub type Block<W> = [[W; 8]; 8];

/// Transpose block `blk` of packets `0..lanes` from a contiguous packet buffer
/// (`count * PKT` bytes) into bitslice form.
#[inline(always)]
pub fn load_block<W: Word>(packets: &[u8], lanes: usize, blk: usize) -> Block<W> {
    debug_assert!(lanes <= MAX_LANES && lanes <= W::LANES);
    let mut w = [[W::zero(); 8]; 8];
    let mut col = [0u8; MAX_LANES];
    for byte in 0 .. 8 {
        for p in 0 .. lanes {
            col[p] = packets[p * PKT + HDR + blk * BLK + byte];
        }
        w[byte] = W::gather_bitplanes(&col[0 .. lanes]);
    }
    w
}

/// Byte-domain load of block `blk`: `out[j][p]` = byte `j` of packet `p`.
/// Groups of 8 packets move as whole `u64` rows through an 8x8 byte transpose.
#[inline(always)]
pub fn load_block_bytes(packets: &[u8], lanes: usize, blk: usize, out: &mut [[u8; MAX_LANES]; 8]) {
    debug_assert!(lanes <= MAX_LANES);
    let full = lanes & !7;
    for p in (0 .. full).step_by(8) {
        let mut r = [0u64; 8];
        for (k, r) in r.iter_mut().enumerate() {
            let o = (p + k) * PKT + HDR + blk * BLK;
            *r = u64::from_le_bytes(packets[o .. o + 8].try_into().unwrap());
        }
        transpose8x8_bytes(&mut r);
        for j in 0 .. BLK {
            out[j][p .. p + 8].copy_from_slice(&r[j].to_le_bytes());
        }
    }
    for j in 0 .. BLK {
        for p in full .. lanes {
            out[j][p] = packets[p * PKT + HDR + blk * BLK + j];
        }
    }
}

/// 8x8 byte transpose: byte `j` of `r[k]` <-> byte `k` of `r[j]`.
#[inline(always)]
fn transpose8x8_bytes(r: &mut [u64; 8]) {
    for (d, m) in [
        (4, 0x0000_0000_FFFF_FFFFu64),
        (2, 0x0000_FFFF_0000_FFFF),
        (1, 0x00FF_00FF_00FF_00FF),
    ] {
        let sh = 8 * d as u32;
        for k in (0 .. 8).filter(|k| k & d == 0) {
            let (a, b) = (r[k], r[k + d]);
            r[k] = (a & m) | ((b & m) << sh);
            r[k + d] = ((a >> sh) & m) | (b & !m);
        }
    }
}

/// Inverse of [`load_block_bytes`]: scatter 8 byte-planes back to block `blk` for
/// packets `0..lanes`. Unused/garbage lanes are never written.
#[inline(always)]
pub fn store_block_bytes(
    planes: &[[u8; MAX_LANES]; 8],
    packets: &mut [u8],
    lanes: usize,
    blk: usize,
) {
    debug_assert!(lanes <= MAX_LANES);
    let full = lanes & !7;
    for p in (0 .. full).step_by(8) {
        let mut r = [0u64; 8];
        for (j, r) in r.iter_mut().enumerate() {
            *r = u64::from_le_bytes(planes[j][p .. p + 8].try_into().unwrap());
        }
        transpose8x8_bytes(&mut r);
        for (k, r) in r.iter().enumerate() {
            let o = (p + k) * PKT + HDR + blk * BLK;
            packets[o .. o + 8].copy_from_slice(&r.to_le_bytes());
        }
    }
    for j in 0 .. BLK {
        for p in full .. lanes {
            packets[p * PKT + HDR + blk * BLK + j] = planes[j][p];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference bit-by-bit 8x8 transpose, independent of `transpose8`.
    fn transpose8_ref(m: u64) -> u64 {
        let mut r = 0u64;
        for k in 0 .. 8 {
            for b in 0 .. 8 {
                r |= ((m >> (8 * k + b)) & 1) << (8 * b + k);
            }
        }
        r
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    #[test]
    fn transpose8_matches_reference() {
        let mut rng = Rng(1);
        for _ in 0 .. 100_000 {
            let m = rng.next();
            assert_eq!(transpose8(m), transpose8_ref(m));
            assert_eq!(transpose8(transpose8(m)), m);
        }
    }

    // A naive, obviously-correct transpose used only to cross-check the fast one.
    fn naive_gather(col: &[u8], lanes: usize) -> [[u64; 8]; 1] {
        // returns a single-limb plane set for u64 (lanes <= 64)
        let mut planes = [0u64; 8];
        for (p, &v) in col.iter().enumerate().take(lanes) {
            for bit in 0 .. 8 {
                if (v >> bit) & 1 == 1 {
                    planes[bit] |= 1u64 << p;
                }
            }
        }
        [planes]
    }

    #[test]
    fn gather64_matches_naive() {
        let mut rng = Rng(42);
        for &lanes in &[1usize, 5, 8, 31, 63, 64] {
            let mut col = [0u8; 64];
            for c in col.iter_mut().take(lanes) {
                *c = rng.next() as u8;
            }
            let fast = gather64(&col[0 .. lanes]);
            let naive = naive_gather(&col[0 .. lanes], lanes)[0];
            assert_eq!(fast, naive, "gather mismatch at lanes {lanes}");
            // round-trip
            let mut back = [0u8; 64];
            scatter64(&fast, &mut back[0 .. lanes]);
            assert_eq!(
                &back[0 .. lanes],
                &col[0 .. lanes],
                "scatter mismatch at lanes {lanes}"
            );
        }
    }

    #[test]
    fn byte_transpose_round_trip() {
        let mut rng = Rng(0x5EED_1234);
        for &count in &[1usize, 7, 63, 64] {
            let mut buf = vec![0u8; count * PKT];
            for b in buf.iter_mut() {
                *b = rng.next() as u8;
            }
            let orig = buf.clone();
            for blk in 0 .. BLOCKS {
                let mut planes = [[0u8; MAX_LANES]; 8];
                load_block_bytes(&buf, count, blk, &mut planes);
                // naive cross-check of the load
                for j in 0 .. BLK {
                    for p in 0 .. count {
                        assert_eq!(planes[j][p], orig[p * PKT + HDR + blk * BLK + j]);
                    }
                }
                for b in buf.iter_mut() {
                    *b ^= 0xA5;
                }
                store_block_bytes(&planes, &mut buf, count, blk);
                for p in 0 .. count {
                    let base = p * PKT + HDR + blk * BLK;
                    assert_eq!(&buf[base .. base + BLK], &orig[base .. base + BLK]);
                }
                buf.copy_from_slice(&orig);
            }
        }
    }
}
