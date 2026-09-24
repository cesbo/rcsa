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
            // u64 words keep LLVM from vectorizing into port-5-bound pextrb/pinsrb chains.
            let k = u64::from(kk_i) * 0x0101_0101_0101_0101;
            for g in (0 .. n).step_by(8) {
                let x = u64::from_le_bytes(src[g .. g + 8].try_into().unwrap()) ^ k;
                let mut y = 0u64;
                for b in 0 .. 8 {
                    y |=
                        u64::from(crate::csa::BLOCK_SBOX[(x >> (8 * b)) as u8 as usize]) << (8 * b);
                }
                raw[g .. g + 8].copy_from_slice(&y.to_le_bytes());
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

/// Invert the CSA block cipher for one 8-byte block in the byte domain
/// (`W::LANES` lanes, one byte per lane; padding lanes are harmless). On entry `p`
/// holds the byte-planes of the block-cipher output; on exit `out_ib` holds the
/// byte-planes of the input that produce `p`. The cipher's shift register is run
/// forward (`t[0..8] = p`, 56 rounds of S-box + feedback), then the input block is
/// read from `t[56..64]` with the low six bytes corrected for the mixed-in feedback.
#[inline(always)]
pub fn block_encypher<W: Word>(
    p: &[[u8; MAX_LANES]; 8],
    kk: &[u8; 56],
    out_ib: &mut [[u8; MAX_LANES]; 8],
) {
    let n = W::LANES;
    let mut t = [[0u8; MAX_LANES]; 64];
    for j in 0 .. 8 {
        t[j] = p[j]; // t[0..8] = p
    }
    let mut so = [[0u8; MAX_LANES]; 56];
    let mut s = [[0u8; MAX_LANES]; 56];
    for i in 0 .. 56 {
        let kk_i = kk[i];
        // sbox_in = t[i+7] ^ kk[i]; s = SBOX[in]   (one scalar lookup)
        for g in 0 .. n {
            s[i][g] = crate::csa::BLOCK_SBOX[(t[i + 7][g] ^ kk_i) as usize];
        }
        // so[i] = t[i] ^ so[i-2] ^ so[i-3] ^ so[i-4] ^ PERM(s[i-6]); t[i+8] = s[i] ^ so[i]
        for g in 0 .. n {
            let mut o = t[i][g];
            if i >= 2 {
                o ^= so[i - 2][g];
            }
            if i >= 3 {
                o ^= so[i - 3][g];
            }
            if i >= 4 {
                o ^= so[i - 4][g];
            }
            if i >= 6 {
                o ^= perm_byte(s[i - 6][g]);
            }
            so[i][g] = o;
            t[i + 8][g] = s[i][g] ^ o;
        }
    }
    for g in 0 .. n {
        out_ib[0][g] = t[56][g] ^ so[54][g] ^ so[53][g] ^ so[52][g] ^ perm_byte(s[50][g]);
        out_ib[1][g] = t[57][g] ^ so[55][g] ^ so[54][g] ^ so[53][g] ^ perm_byte(s[51][g]);
        out_ib[2][g] = t[58][g] ^ so[55][g] ^ so[54][g] ^ perm_byte(s[52][g]);
        out_ib[3][g] = t[59][g] ^ so[55][g] ^ perm_byte(s[53][g]);
        out_ib[4][g] = t[60][g] ^ perm_byte(s[54][g]);
        out_ib[5][g] = t[61][g] ^ perm_byte(s[55][g]);
        out_ib[6][g] = t[62][g];
        out_ib[7][g] = t[63][g];
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

    #[test]
    fn byte_block_encypher_inverts_scalar() {
        let mut s = 0xFEDC_BA98_7654_3210u64;
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
            let mut p = [[0u8; MAX_LANES]; 8];
            for g in 0 .. 64 {
                let mut ib = [0u8; 8];
                for b in ib.iter_mut() {
                    *b = nextb();
                }
                inputs[g] = ib;
                let out = scalar_block(&ib, &kk);
                for j in 0 .. 8 {
                    p[j][g] = out[j];
                }
            }
            let mut rec = [[0u8; MAX_LANES]; 8];
            block_encypher::<u64>(&p, &kk, &mut rec);
            for g in 0 .. 64 {
                for j in 0 .. 8 {
                    assert_eq!(rec[j][g], inputs[g][j], "lane {g} byte {j}");
                }
            }
        }
    }
}
