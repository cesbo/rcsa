//! Bitslice port of the CSA block cipher (`Csa::block_decypher`, src/csa.rs).

use crate::bs::{
    sbox::{
        BLOCK_PERM_BITS,
        block_sbox,
    },
    word::{
        Block,
        Word,
    },
};

/// Broadcast round-key masks: `kk[i][b]` is all-ones where key bit `b` of round
/// byte `i` is set, else all-zeros (the same CW is used for the whole batch).
pub type KkMask<W> = [[W; 8]; 56];

/// Decrypt one 8-byte block into the 64-byte state `t` (`[byte][bit]`).
/// Faithful to the scalar `block_decypher`: `t6` is a register seeded from
/// `ib[6]`; the S-box output feeds the `T[i+6]` update *permuted* and the
/// `T[i+4..i]` updates *raw*.
#[inline(always)]
pub fn block_decypher<W: Word>(t: &mut [[W; 8]; 64], ib: &Block<W>, kk: &KkMask<W>) {
    t[56 .. 64].copy_from_slice(ib);
    let mut t6: [W; 8] = t[62]; // == ib[6]

    for i in (0 ..= 55).rev() {
        for b in 0 .. 8 {
            t6[b] = t6[b] ^ kk[i][b];
        }
        let sbox = block_sbox(t6);

        // t6 = T[i+6] ^ PERM[sbox]; T[i+6] = t6   (uses the PERMUTED output)
        let mut perm = [W::zero(); 8];
        for k in 0 .. 8 {
            perm[BLOCK_PERM_BITS[k]] = sbox[k];
        }
        for b in 0 .. 8 {
            t6[b] = t[i + 6][b] ^ perm[b];
            t[i + 6][b] = t6[b];
        }

        // so = raw sbox ^ T[i+8]   (uses the RAW, unpermuted output)
        let mut so = sbox;
        for b in 0 .. 8 {
            so[b] = so[b] ^ t[i + 8][b];
        }
        for b in 0 .. 8 {
            t[i + 4][b] = t[i + 4][b] ^ so[b];
            t[i + 3][b] = t[i + 3][b] ^ so[b];
            t[i + 2][b] = t[i + 2][b] ^ so[b];
            t[i][b] = so[b];
        }
    }
}
