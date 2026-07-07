//! Byte-domain port of the CSA block cipher (`Csa::block_decypher`, src/csa.rs).
//!
//! One byte per lane (packet). The 8->8 S-box is a scalar 256-entry table lookup
//! per lane -- the work FFdecsa deliberately does NOT bitslice ("8 input bits are
//! too many"). The bit permutation is a per-byte shuffle of 6 masked shifts (the
//! `[1,7,5,4,2,6,0,3]` bit map, same as FFdecsa's B_FFSH8), applied over
//! byte-planes so it autovectorizes; only the single S-box lookup stays scalar.
//! There is no 663-gate circuit and no per-block bit transpose here.

use crate::bs::word::{
    MAX_LANES,
    Word,
};

/// Apply the CSA block bit-permutation to one byte: bit `k` -> bit
/// `BLOCK_PERM_BITS[k]` for the map `[1,7,5,4,2,6,0,3]`. Equal to
/// `csa::BLOCK_PERM[x]` (checked exhaustively by `shift_perm_matches_block_perm`).
/// Every masked bit stays inside the byte, so this is safe to run lane-parallel.
#[inline(always)]
fn perm_byte(x: u8) -> u8 {
    ((x & 0x29) << 1)
        | ((x & 0x02) << 6)
        | ((x & 0x04) << 3)
        | ((x & 0x10) >> 2)
        | ((x & 0x40) >> 6)
        | ((x & 0x80) >> 4)
}

/// Decrypt one 8-byte block in byte domain. On entry `ib` holds the 8 input
/// byte-planes; on exit `t[0..8]` holds the block output. Processes `W::LANES`
/// lanes (padding lanes are harmless). Faithful, per lane, to the scalar
/// `Csa::block_decypher`: `t6` on entry to round `i` is plane `t[i+7]`; the S-box
/// output feeds the `t[i+6]` update *permuted* and the `t[i+4..=i]` updates *raw*.
#[inline(always)]
pub fn block_decypher<W: Word>(
    t: &mut [[u8; MAX_LANES]; 64],
    ib: &[[u8; MAX_LANES]; 8],
    kk: &[u8; 56],
) {
    let n = W::LANES;
    for j in 0 .. 8 {
        t[56 + j] = ib[j]; // t[56..64] = ib
    }
    let mut raw = [0u8; MAX_LANES];
    for i in (0 ..= 55).rev() {
        let kk_i = kk[i];
        // (a)+(b): sbox_in = t[i+7] ^ kk[i]; raw = SBOX[in]   (one scalar lookup)
        {
            let src = &t[i + 7]; // scalar t6 on entry == t[i+7]
            for g in 0 .. n {
                raw[g] = crate::csa::BLOCK_SBOX[(src[g] ^ kk_i) as usize];
            }
        }
        // (c): t[i+6] ^= PERM[sbox_out]   (permutation via masked shifts)
        for g in 0 .. n {
            t[i + 6][g] ^= perm_byte(raw[g]);
        }
        // (d): so = sbox_out ^ t[i+8]; t[i+4]^=so; t[i+3]^=so; t[i+2]^=so; t[i]=so
        for g in 0 .. n {
            let so = raw[g] ^ t[i + 8][g];
            t[i + 4][g] ^= so;
            t[i + 3][g] ^= so;
            t[i + 2][g] ^= so;
            t[i][g] = so;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent scalar reference (mirrors Csa::block_decypher, src/csa.rs).
    fn scalar_block(ib: &[u8; 8], kk: &[u8; 56]) -> [u8; 8] {
        let mut tt = [0u8; 64];
        tt[56 .. 64].copy_from_slice(ib);
        let mut t6 = ib[6];
        for i in (0 ..= 55).rev() {
            t6 ^= kk[i];
            let s = crate::csa::BLOCK_SBOX[t6 as usize];
            t6 = tt[i + 6] ^ crate::csa::BLOCK_PERM[s as usize];
            tt[i + 6] = t6;
            let so = s ^ tt[i + 8];
            tt[i + 4] ^= so;
            tt[i + 3] ^= so;
            tt[i + 2] ^= so;
            tt[i] = so;
        }
        let mut out = [0u8; 8];
        out.copy_from_slice(&tt[0 .. 8]);
        out
    }

    #[test]
    fn shift_perm_matches_block_perm() {
        // The 6-shift permutation must reproduce the scalar oracle's BLOCK_PERM
        // table exactly (this is the bit-order footgun; check all 256 inputs).
        for x in 0 .. 256usize {
            assert_eq!(perm_byte(x as u8), crate::csa::BLOCK_PERM[x], "x={x:#04x}");
        }
    }

    #[test]
    fn byte_block_matches_scalar() {
        let mut s = 0x1234_5678_9ABC_DEF0u64;
        let mut nextb = || {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
            (s >> 33) as u8
        };
        for _ in 0 .. 500 {
            let mut kk = [0u8; 56];
            for k in kk.iter_mut() {
                *k = nextb();
            }
            let mut inputs = [[0u8; 8]; 64];
            let mut ib = [[0u8; MAX_LANES]; 8];
            for g in 0 .. 64 {
                for j in 0 .. 8 {
                    let b = nextb();
                    inputs[g][j] = b;
                    ib[j][g] = b;
                }
            }
            let mut t = [[0u8; MAX_LANES]; 64];
            block_decypher::<u64>(&mut t, &ib, &kk);
            for g in 0 .. 64 {
                let exp = scalar_block(&inputs[g], &kk);
                for j in 0 .. 8 {
                    assert_eq!(t[j][g], exp[j], "lane {g} byte {j}");
                }
            }
        }
    }
}
