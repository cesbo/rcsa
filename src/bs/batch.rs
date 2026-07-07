//! Public batch API: in-place, bitsliced descrambling of many TS packets.
//!
//! [`CsaBatch`] holds the expanded key and descrambles a contiguous buffer of
//! concatenated 188-byte packets in place, processing `Word::LANES` packets per
//! machine word. On x86-64 with AVX2 it uses 256-wide words; otherwise 64-wide
//! `u64` words. Only the 184-byte payloads are rewritten; TS headers are left
//! untouched.

use crate::bs::{
    block::{
        KkMask,
        block_decypher,
    },
    nibble::Nibble,
    stream::StreamState,
    word::{
        BLOCKS,
        PKT,
        Word,
        load_block,
        store_block,
    },
};

/// Batch DVB-CSA descrambler for a fixed control word.
pub struct CsaBatch {
    cw: [u8; 8],
    kk: [u8; 56],
}

impl CsaBatch {
    /// Create a descrambler for control word `cw`.
    pub fn new(cw: &[u8; 8]) -> Self {
        let mut s = CsaBatch {
            cw: [0; 8],
            kk: [0; 56],
        };
        s.set_cw(cw);
        s
    }

    /// Re-key with a new control word (same schedule as the scalar `Csa`).
    pub fn set_cw(&mut self, cw: &[u8; 8]) {
        self.cw = *cw;
        crate::key::expand_key(&mut self.kk, cw);
    }

    /// Descramble a contiguous buffer of concatenated 188-byte TS packets in
    /// place. `packets.len()` must be a multiple of 188. Selects the AVX2
    /// backend at runtime when available, else the portable `u64` backend.
    pub fn decrypt_in_place(&self, packets: &mut [u8]) {
        assert!(
            packets.len() % PKT == 0,
            "buffer length must be a multiple of 188"
        );
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx2") {
                // SAFETY: guarded by runtime AVX2 detection.
                unsafe {
                    self.descramble_avx2(packets);
                }
                return;
            }
        }
        self.descramble::<u64>(packets);
    }

    /// Force the portable 64-wide backend (mainly for benchmarks/tests).
    #[doc(hidden)]
    pub fn decrypt_in_place_u64(&self, packets: &mut [u8]) {
        assert!(
            packets.len() % PKT == 0,
            "buffer length must be a multiple of 188"
        );
        self.descramble::<u64>(packets);
    }

    /// Force the AVX2 256-wide backend. Panics if AVX2 is unavailable.
    #[doc(hidden)]
    #[cfg(target_arch = "x86_64")]
    pub fn decrypt_in_place_avx2(&self, packets: &mut [u8]) {
        assert!(
            packets.len() % PKT == 0,
            "buffer length must be a multiple of 188"
        );
        assert!(std::is_x86_feature_detected!("avx2"), "AVX2 not available");
        // SAFETY: asserted above.
        unsafe {
            self.descramble_avx2(packets);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn descramble_avx2(&self, packets: &mut [u8]) {
        self.descramble::<crate::bs::avx2::W256>(packets);
    }

    // `inline(always)` throughout the W256 chain so it collapses into the
    // `descramble_avx2` `#[target_feature]` root and the SIMD ops fuse to AVX2.
    #[inline(always)]
    fn descramble<W: Word>(&self, packets: &mut [u8]) {
        let kk = kk_mask::<W>(&self.kk);
        let ccw = ccw_bits::<W>(&self.cw);
        let total = packets.len() / PKT;
        let mut done = 0;
        while done < total {
            let lanes = core::cmp::min(W::LANES, total - done);
            let group = &mut packets[done * PKT .. (done + lanes) * PKT];
            descramble_group::<W>(&kk, &ccw, group, lanes);
            done += lanes;
        }
    }
}

#[inline(always)]
fn kk_mask<W: Word>(kk: &[u8; 56]) -> KkMask<W> {
    let mut m = [[W::zero(); 8]; 56];
    for i in 0 .. 56 {
        for b in 0 .. 8 {
            m[i][b] = W::splat((kk[i] >> b) & 1 == 1);
        }
    }
    m
}

/// Broadcast the 16 CW nibbles, matching `Csa::set_cw`: `ccw[2i]` = high nibble
/// of `cw[i]` (bits 4..8), `ccw[2i+1]` = low nibble (bits 0..4), LSB-first.
#[inline(always)]
fn ccw_bits<W: Word>(cw: &[u8; 8]) -> [Nibble<W>; 16] {
    let mut ccw = [Nibble::zero(); 16];
    for i in 0 .. 8 {
        let hi = cw[i] >> 4;
        ccw[2 * i] = Nibble(
            W::splat(hi & 1 == 1),
            W::splat((hi >> 1) & 1 == 1),
            W::splat((hi >> 2) & 1 == 1),
            W::splat((hi >> 3) & 1 == 1),
        );
        let lo = cw[i];
        ccw[2 * i + 1] = Nibble(
            W::splat(lo & 1 == 1),
            W::splat((lo >> 1) & 1 == 1),
            W::splat((lo >> 2) & 1 == 1),
            W::splat((lo >> 3) & 1 == 1),
        );
    }
    ccw
}

/// Descramble up to `W::LANES` packets (`lanes` valid) in place.
#[inline(always)]
fn descramble_group<W: Word>(
    kk: &KkMask<W>,
    ccw: &[Nibble<W>; 16],
    group: &mut [u8],
    lanes: usize,
) {
    // Transpose the whole payload in up front, so writing plaintext back can
    // never clobber a ciphertext block that is still needed.
    let mut ct = [[[W::zero(); 8]; 8]; BLOCKS];
    for (k, c) in ct.iter_mut().enumerate() {
        *c = load_block::<W>(group, lanes, k);
    }

    // Block-cipher state; zero-init is correct (T is fully rebuilt each block).
    let mut t = [[W::zero(); 8]; 64];

    let mut st = StreamState::<W>::new();
    st.stream_init(ccw);
    st.stream_cypher_init(&ct[0]);

    // Running block, kept in bitslice; starts as ciphertext block 0.
    let mut block = ct[0];

    for i in 0 .. 22 {
        block_decypher::<W>(&mut t, &block, kk);
        let ks = st.stream_cypher();
        let mut pt = [[W::zero(); 8]; 8];
        for byte in 0 .. 8 {
            for bit in 0 .. 8 {
                let nb = ks[byte][bit] ^ ct[i + 1][byte][bit];
                block[byte][bit] = nb;
                pt[byte][bit] = nb ^ t[byte][bit];
            }
        }
        store_block::<W>(&pt, group, lanes, i);
    }

    block_decypher::<W>(&mut t, &block, kk);
    let mut last = [[W::zero(); 8]; 8];
    last.copy_from_slice(&t[0 .. 8]);
    store_block::<W>(&last, group, lanes, 22);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Csa;

    include!("../../fixtures/dvb_csa.rs");

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn byte(&mut self) -> u8 {
            self.next() as u8
        }
    }

    /// Scalar oracle: decrypt one packet with a fresh `Csa`.
    fn scalar(cw: &[u8; 8], pkt: &[u8]) -> Vec<u8> {
        let mut c = Csa::default();
        c.set_cw(cw);
        let mut out = vec![0u8; pkt.len()];
        c.decrypt(pkt, &mut out);
        out
    }

    #[test]
    fn batch_kat_u64() {
        let n = 64;
        let mut buf = TS_SCRAMBLED.repeat(n);
        CsaBatch::new(&CW).decrypt_in_place_u64(&mut buf);
        for p in 0 .. n {
            assert_eq!(&buf[p * PKT .. (p + 1) * PKT], TS_CLEAR, "lane {p}");
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn batch_kat_avx2() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }
        let n = 256;
        let mut buf = TS_SCRAMBLED.repeat(n);
        CsaBatch::new(&CW).decrypt_in_place_avx2(&mut buf);
        for p in 0 .. n {
            assert_eq!(&buf[p * PKT .. (p + 1) * PKT], TS_CLEAR, "lane {p}");
        }
    }

    fn differential(mut run: impl FnMut(&CsaBatch, &mut [u8]), iters: usize, max: usize) {
        let mut rng = Rng(0x0BAD_F00D_1234_5678);
        for _ in 0 .. iters {
            let mut cw = [0u8; 8];
            for x in cw.iter_mut() {
                *x = rng.byte();
            }
            let count = 1 + (rng.next() as usize) % max;
            let mut buf = vec![0u8; count * PKT];
            for x in buf.iter_mut() {
                *x = rng.byte();
            }
            let mut expect = buf.clone();
            for p in 0 .. count {
                let out = scalar(&cw, &buf[p * PKT .. (p + 1) * PKT]);
                expect[p * PKT .. (p + 1) * PKT].copy_from_slice(&out);
            }
            let batch = CsaBatch::new(&cw);
            run(&batch, &mut buf);
            for p in 0 .. count {
                assert_eq!(
                    &buf[p * PKT .. (p + 1) * PKT],
                    &expect[p * PKT .. (p + 1) * PKT],
                    "packet {p} of {count} diverged"
                );
            }
        }
    }

    #[test]
    fn differential_vs_scalar_u64() {
        differential(|b, buf| b.decrypt_in_place_u64(buf), 100, 200);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn differential_vs_scalar_avx2() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }
        differential(|b, buf| b.decrypt_in_place_avx2(buf), 20, 600);
    }

    #[test]
    fn partial_batches_u64() {
        let mut rng = Rng(0xC0FF_EE00);
        let mut cw = [0u8; 8];
        for x in cw.iter_mut() {
            *x = rng.byte();
        }
        for &count in &[1usize, 3, 63, 64, 65, 127, 128, 131] {
            let mut buf = vec![0u8; count * PKT];
            for x in buf.iter_mut() {
                *x = rng.byte();
            }
            let mut expect = buf.clone();
            for p in 0 .. count {
                let out = scalar(&cw, &buf[p * PKT .. (p + 1) * PKT]);
                expect[p * PKT .. (p + 1) * PKT].copy_from_slice(&out);
            }
            CsaBatch::new(&cw).decrypt_in_place_u64(&mut buf);
            assert_eq!(buf, expect, "count {count}");
        }
    }
}
