//! Public batch API: in-place, bitsliced descrambling of many TS packets.
//!
//! [`CsaBatch`] holds the expanded key and descrambles a contiguous buffer of
//! concatenated 188-byte packets in place, processing `Word::LANES` packets per
//! machine word. On x86-64 with AVX2 it uses 256-wide words; otherwise 64-wide
//! `u64` words. Only the 184-byte payloads are rewritten; TS headers are left
//! untouched.

use crate::bs::{
    block::{
        block_decypher,
        block_encypher,
    },
    nibble::Nibble,
    stream::StreamState,
    word::{
        BLOCKS,
        MAX_LANES,
        PKT,
        Word,
        load_block,
        load_block_bytes,
        store_block_bytes,
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
    /// place. `packets.len()` must be a multiple of 188.
    ///
    /// Picks the widest backend the batch actually *fills*:
    /// - AVX2 (256 lanes) for ≥256 packets when the CPU has it
    /// - SSE2 (128 lanes, x86-64 baseline) for ≥128 packets
    /// - `u64` (64 lanes) on non-x86.
    pub fn decrypt_in_place(&self, packets: &mut [u8]) {
        assert!(
            packets.len() % PKT == 0,
            "buffer length must be a multiple of 188"
        );
        #[cfg(target_arch = "x86_64")]
        {
            let n = packets.len() / PKT;
            if n >= <crate::bs::avx2::W256 as Word>::LANES && crate::bs::avx2::available() {
                // SAFETY: guarded by runtime AVX2 detection.
                unsafe {
                    self.descramble_avx2(packets);
                }
                return;
            }
            if n >= <crate::bs::sse2::W128 as Word>::LANES {
                // SAFETY: SSE2 is guaranteed present on every x86-64 target.
                unsafe {
                    self.descramble_sse2(packets);
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
        assert!(crate::bs::avx2::available(), "AVX2 not available");
        // SAFETY: asserted above.
        unsafe {
            self.descramble_avx2(packets);
        }
    }

    /// Force the SSE2 128-wide backend. SSE2 is baseline on x86-64, so this is
    /// always available; it is the natural fallback when AVX2 is absent.
    #[doc(hidden)]
    #[cfg(target_arch = "x86_64")]
    pub fn decrypt_in_place_sse2(&self, packets: &mut [u8]) {
        assert!(
            packets.len() % PKT == 0,
            "buffer length must be a multiple of 188"
        );
        // SAFETY: SSE2 is guaranteed present on every x86-64 target.
        unsafe {
            self.descramble_sse2(packets);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn descramble_avx2(&self, packets: &mut [u8]) {
        self.descramble::<crate::bs::avx2::W256>(packets);
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse2")]
    unsafe fn descramble_sse2(&self, packets: &mut [u8]) {
        self.descramble::<crate::bs::sse2::W128>(packets);
    }

    // `inline(always)` throughout the W256 chain so it collapses into the
    // `descramble_avx2` `#[target_feature]` root and the SIMD ops fuse to AVX2.
    #[inline(always)]
    fn descramble<W: Word>(&self, packets: &mut [u8]) {
        let ccw = ccw_bits::<W>(&self.cw);
        let total = packets.len() / PKT;
        let mut done = 0;
        while done < total {
            let lanes = core::cmp::min(W::LANES, total - done);
            let group = &mut packets[done * PKT .. (done + lanes) * PKT];
            descramble_group::<W>(&self.kk, &ccw, group, lanes);
            done += lanes;
        }
    }

    /// Scramble a contiguous buffer of concatenated 188-byte TS packets in
    /// place. `packets.len()` must be a multiple of 188.
    ///
    /// Picks the widest backend the batch actually *fills*:
    /// - AVX2 (256 lanes) for ≥256 packets when the CPU has it
    /// - SSE2 (128 lanes, x86-64 baseline) for ≥128 packets
    /// - `u64` (64 lanes) on non-x86.
    pub fn encrypt_in_place(&self, packets: &mut [u8]) {
        assert!(
            packets.len() % PKT == 0,
            "buffer length must be a multiple of 188"
        );
        #[cfg(target_arch = "x86_64")]
        {
            let n = packets.len() / PKT;
            if n >= <crate::bs::avx2::W256 as Word>::LANES && crate::bs::avx2::available() {
                // SAFETY: guarded by runtime AVX2 detection.
                unsafe {
                    self.scramble_avx2(packets);
                }
                return;
            }
            if n >= <crate::bs::sse2::W128 as Word>::LANES {
                // SAFETY: SSE2 is guaranteed present on every x86-64 target.
                unsafe {
                    self.scramble_sse2(packets);
                }
                return;
            }
        }
        self.scramble::<u64>(packets);
    }

    /// Force the portable 64-wide backend (mainly for benchmarks/tests).
    #[doc(hidden)]
    pub fn encrypt_in_place_u64(&self, packets: &mut [u8]) {
        assert!(
            packets.len() % PKT == 0,
            "buffer length must be a multiple of 188"
        );
        self.scramble::<u64>(packets);
    }

    /// Force the AVX2 256-wide backend. Panics if AVX2 is unavailable.
    #[doc(hidden)]
    #[cfg(target_arch = "x86_64")]
    pub fn encrypt_in_place_avx2(&self, packets: &mut [u8]) {
        assert!(
            packets.len() % PKT == 0,
            "buffer length must be a multiple of 188"
        );
        assert!(crate::bs::avx2::available(), "AVX2 not available");
        // SAFETY: asserted above.
        unsafe {
            self.scramble_avx2(packets);
        }
    }

    /// Force the SSE2 128-wide backend. SSE2 is baseline on x86-64, so this is
    /// always available; it is the natural fallback when AVX2 is absent.
    #[doc(hidden)]
    #[cfg(target_arch = "x86_64")]
    pub fn encrypt_in_place_sse2(&self, packets: &mut [u8]) {
        assert!(
            packets.len() % PKT == 0,
            "buffer length must be a multiple of 188"
        );
        // SAFETY: SSE2 is guaranteed present on every x86-64 target.
        unsafe {
            self.scramble_sse2(packets);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn scramble_avx2(&self, packets: &mut [u8]) {
        self.scramble::<crate::bs::avx2::W256>(packets);
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse2")]
    unsafe fn scramble_sse2(&self, packets: &mut [u8]) {
        self.scramble::<crate::bs::sse2::W128>(packets);
    }

    // `inline(always)` throughout the W256 chain so it collapses into the
    // `scramble_avx2` `#[target_feature]` root and the SIMD ops fuse to AVX2.
    #[inline(always)]
    fn scramble<W: Word>(&self, packets: &mut [u8]) {
        let ccw = ccw_bits::<W>(&self.cw);
        let total = packets.len() / PKT;
        let mut done = 0;
        while done < total {
            let lanes = core::cmp::min(W::LANES, total - done);
            let group = &mut packets[done * PKT .. (done + lanes) * PKT];
            scramble_group::<W>(&self.kk, &ccw, group, lanes);
            done += lanes;
        }
    }
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
fn descramble_group<W: Word>(kk: &[u8; 56], ccw: &[Nibble<W>; 16], group: &mut [u8], lanes: usize) {
    // 1. Preload all 23 ciphertext blocks in BYTE domain (cheap strided gather), so writing
    //    plaintext back can never clobber ciphertext still needed.
    let mut ct = [[[0u8; MAX_LANES]; 8]; BLOCKS];
    for k in 0 .. BLOCKS {
        load_block_bytes(group, lanes, k, &mut ct[k]);
    }

    // 2. Byte-domain block-cipher state; zero-init once (T is fully rebuilt each block -- same
    //    invariant as the bitsliced path).
    let mut t = [[0u8; MAX_LANES]; 64];

    // 3. Stream cipher stays bitsliced; its seed needs block 0 in bitslice form.
    let seed = load_block::<W>(group, lanes, 0);
    let mut st = StreamState::<W>::new();
    st.stream_init(ccw);
    st.stream_cypher_init(&seed);

    // 4. Running block-cipher input (byte domain); starts as ciphertext block 0.
    let mut block = ct[0];
    let mut ks_bytes = [[0u8; MAX_LANES]; 8];
    let mut pt = [[0u8; MAX_LANES]; 8];

    for i in 0 .. 22 {
        block_decypher::<W>(&mut t, &block, kk); // t[0..8] = byte-domain output
        let ks = st.stream_cypher(); // bitsliced Block<W>
        for j in 0 .. 8 {
            W::scatter_bitplanes(&ks[j], &mut ks_bytes[j][0 .. lanes]); // bit -> byte
        }
        for j in 0 .. 8 {
            for g in 0 .. lanes {
                let nb = ks_bytes[j][g] ^ ct[i + 1][j][g];
                block[j][g] = nb; // next cipher input
                pt[j][g] = nb ^ t[j][g]; // plaintext
            }
        }
        store_block_bytes(&pt, group, lanes, i);
    }

    // Last block: plaintext is t[0..8] directly (no keystream/ciphertext combine).
    block_decypher::<W>(&mut t, &block, kk);
    let mut last = [[0u8; MAX_LANES]; 8];
    last.copy_from_slice(&t[0 .. 8]);
    store_block_bytes(&last, group, lanes, 22);
}

/// Scramble up to `W::LANES` packets (`lanes` valid) in place.
#[inline(always)]
fn scramble_group<W: Word>(kk: &[u8; 56], ccw: &[Nibble<W>; 16], group: &mut [u8], lanes: usize) {
    // 1. Load all 23 plaintext blocks in BYTE domain (cheap strided gather).
    let mut p = [[[0u8; MAX_LANES]; 8]; BLOCKS];
    for k in 0 .. BLOCKS {
        load_block_bytes(group, lanes, k, &mut p[k]);
    }

    // 2. Backward block-cipher chain: IB[22] = BCinv(P[22]); IB[i] = BCinv(P[i] ^ IB[i+1]) for i =
    //    21..=0.
    let mut ib = [[[0u8; MAX_LANES]; 8]; BLOCKS];
    block_encypher::<W>(&p[22], kk, &mut ib[22]);
    let mut x = [[0u8; MAX_LANES]; 8];
    for i in (0 .. 22).rev() {
        for j in 0 .. 8 {
            for g in 0 .. lanes {
                x[j][g] = p[i][j][g] ^ ib[i + 1][j][g];
            }
        }
        block_encypher::<W>(&x, kk, &mut ib[i]);
    }

    // 3. SB[0] = IB[0]: block 0 is the stream seed, not keystream-XORed.
    store_block_bytes(&ib[0], group, lanes, 0);

    // Seed the (bitsliced) stream cipher from SB[0] = IB[0], same as decrypt
    // seeds from SB[0] (byte planes -> bitslice form).
    let mut seed = [[W::zero(); 8]; 8];
    for j in 0 .. 8 {
        seed[j] = W::gather_bitplanes(&ib[0][j][0 .. lanes]);
    }
    let mut st = StreamState::<W>::new();
    st.stream_init(ccw);
    st.stream_cypher_init(&seed);

    // 4. SB[k] = IB[k] ^ KS[k-1] for k = 1..22.
    let mut ks_bytes = [[0u8; MAX_LANES]; 8];
    let mut sb = [[0u8; MAX_LANES]; 8];
    for k in 1 .. BLOCKS {
        let ks = st.stream_cypher(); // bitsliced Block<W>
        for j in 0 .. 8 {
            W::scatter_bitplanes(&ks[j], &mut ks_bytes[j][0 .. lanes]); // bit -> byte
        }
        for j in 0 .. 8 {
            for g in 0 .. lanes {
                sb[j][g] = ib[k][j][g] ^ ks_bytes[j][g];
            }
        }
        store_block_bytes(&sb, group, lanes, k);
    }
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

    /// Scalar oracle: encrypt one packet with a fresh `Csa`.
    fn scalar_encrypt(cw: &[u8; 8], pkt: &[u8]) -> Vec<u8> {
        let mut c = Csa::default();
        c.set_cw(cw);
        let mut out = vec![0u8; pkt.len()];
        c.encrypt(pkt, &mut out);
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
        if !crate::bs::avx2::available() {
            return;
        }
        let n = 256;
        let mut buf = TS_SCRAMBLED.repeat(n);
        CsaBatch::new(&CW).decrypt_in_place_avx2(&mut buf);
        for p in 0 .. n {
            assert_eq!(&buf[p * PKT .. (p + 1) * PKT], TS_CLEAR, "lane {p}");
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn batch_kat_sse2() {
        // SSE2 is baseline on x86-64; no runtime detection needed.
        let n = 128;
        let mut buf = TS_SCRAMBLED.repeat(n);
        CsaBatch::new(&CW).decrypt_in_place_sse2(&mut buf);
        for p in 0 .. n {
            assert_eq!(&buf[p * PKT .. (p + 1) * PKT], TS_CLEAR, "lane {p}");
        }
    }

    #[test]
    fn batch_encrypt_kat_u64() {
        let n = 64;
        let mut buf = TS_CLEAR.repeat(n);
        CsaBatch::new(&CW).encrypt_in_place_u64(&mut buf);
        for p in 0 .. n {
            assert_eq!(&buf[p * PKT .. (p + 1) * PKT], TS_SCRAMBLED, "lane {p}");
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn batch_encrypt_kat_avx2() {
        if !crate::bs::avx2::available() {
            return;
        }
        let n = 256;
        let mut buf = TS_CLEAR.repeat(n);
        CsaBatch::new(&CW).encrypt_in_place_avx2(&mut buf);
        for p in 0 .. n {
            assert_eq!(&buf[p * PKT .. (p + 1) * PKT], TS_SCRAMBLED, "lane {p}");
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn batch_encrypt_kat_sse2() {
        // SSE2 is baseline on x86-64; no runtime detection needed.
        let n = 128;
        let mut buf = TS_CLEAR.repeat(n);
        CsaBatch::new(&CW).encrypt_in_place_sse2(&mut buf);
        for p in 0 .. n {
            assert_eq!(&buf[p * PKT .. (p + 1) * PKT], TS_SCRAMBLED, "lane {p}");
        }
    }

    /// encrypt then decrypt (and decrypt then encrypt) must return the original
    /// buffer, all 188 bytes per packet, header included.
    fn round_trip(
        encrypt: impl Fn(&CsaBatch, &mut [u8]),
        decrypt: impl Fn(&CsaBatch, &mut [u8]),
        count: usize,
        seed: u64,
    ) {
        let mut rng = Rng(seed);
        let mut cw = [0u8; 8];
        for x in cw.iter_mut() {
            *x = rng.byte();
        }
        let mut buf = vec![0u8; count * PKT];
        for x in buf.iter_mut() {
            *x = rng.byte();
        }
        let orig = buf.clone();
        let batch = CsaBatch::new(&cw);
        encrypt(&batch, &mut buf);
        decrypt(&batch, &mut buf);
        assert_eq!(buf, orig, "encrypt->decrypt not identity");
        decrypt(&batch, &mut buf);
        encrypt(&batch, &mut buf);
        assert_eq!(buf, orig, "decrypt->encrypt not identity");
    }

    #[test]
    fn round_trip_u64() {
        round_trip(
            |b, buf| b.encrypt_in_place_u64(buf),
            |b, buf| b.decrypt_in_place_u64(buf),
            100,
            0x1CE0_CEA5_u64,
        );
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn round_trip_avx2() {
        if !crate::bs::avx2::available() {
            return;
        }
        round_trip(
            |b, buf| b.encrypt_in_place_avx2(buf),
            |b, buf| b.decrypt_in_place_avx2(buf),
            300,
            0xAB5_1DE_5EED_u64,
        );
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn round_trip_sse2() {
        round_trip(
            |b, buf| b.encrypt_in_place_sse2(buf),
            |b, buf| b.decrypt_in_place_sse2(buf),
            150,
            0x5EED_C0DE_u64,
        );
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
        if !crate::bs::avx2::available() {
            return;
        }
        differential(|b, buf| b.decrypt_in_place_avx2(buf), 20, 600);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn differential_vs_scalar_sse2() {
        differential(|b, buf| b.decrypt_in_place_sse2(buf), 20, 400);
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

    /// `decrypt_in_place` must be bit-exact at every size, exercising the
    /// size-aware backend crossovers (u64 / SSE2 128 / AVX2 256) and partial
    /// trailing groups.
    #[test]
    fn dispatch_auto_all_sizes() {
        let mut rng = Rng(0xD15_9A7C_4321);
        let mut cw = [0u8; 8];
        for x in cw.iter_mut() {
            *x = rng.byte();
        }
        for &count in &[
            1usize, 63, 64, 65, 127, 128, 129, 200, 255, 256, 257, 384, 512, 700,
        ] {
            let mut buf = vec![0u8; count * PKT];
            for x in buf.iter_mut() {
                *x = rng.byte();
            }
            let mut expect = buf.clone();
            for p in 0 .. count {
                let out = scalar(&cw, &buf[p * PKT .. (p + 1) * PKT]);
                expect[p * PKT .. (p + 1) * PKT].copy_from_slice(&out);
            }
            CsaBatch::new(&cw).decrypt_in_place(&mut buf);
            assert_eq!(buf, expect, "count {count}");
        }
    }

    fn differential_encrypt(mut run: impl FnMut(&CsaBatch, &mut [u8]), iters: usize, max: usize) {
        let mut rng = Rng(0xD00D_FEED_8765_4321);
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
                let out = scalar_encrypt(&cw, &buf[p * PKT .. (p + 1) * PKT]);
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
    fn differential_encrypt_vs_scalar_u64() {
        differential_encrypt(|b, buf| b.encrypt_in_place_u64(buf), 100, 200);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn differential_encrypt_vs_scalar_avx2() {
        if !crate::bs::avx2::available() {
            return;
        }
        differential_encrypt(|b, buf| b.encrypt_in_place_avx2(buf), 20, 600);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn differential_encrypt_vs_scalar_sse2() {
        differential_encrypt(|b, buf| b.encrypt_in_place_sse2(buf), 20, 400);
    }

    #[test]
    fn partial_encrypt_batches_u64() {
        let mut rng = Rng(0xFACE_B00C);
        let mut cw = [0u8; 8];
        for x in cw.iter_mut() {
            *x = rng.byte();
        }
        for &count in &[
            1usize, 3, 63, 64, 65, 127, 128, 129, 200, 255, 256, 257, 384, 512, 700,
        ] {
            let mut buf = vec![0u8; count * PKT];
            for x in buf.iter_mut() {
                *x = rng.byte();
            }
            let mut expect = buf.clone();
            for p in 0 .. count {
                let out = scalar_encrypt(&cw, &buf[p * PKT .. (p + 1) * PKT]);
                expect[p * PKT .. (p + 1) * PKT].copy_from_slice(&out);
            }
            CsaBatch::new(&cw).encrypt_in_place_u64(&mut buf);
            assert_eq!(buf, expect, "count {count}");
        }
    }

    /// `encrypt_in_place` must be bit-exact at every size, exercising the
    /// size-aware backend crossovers (u64 / SSE2 128 / AVX2 256) and partial
    /// trailing groups.
    #[test]
    fn encrypt_dispatch_auto_all_sizes() {
        let mut rng = Rng(0xE4C_1234_9A7C);
        let mut cw = [0u8; 8];
        for x in cw.iter_mut() {
            *x = rng.byte();
        }
        for &count in &[
            1usize, 3, 63, 64, 65, 127, 128, 129, 200, 255, 256, 257, 384, 512, 700,
        ] {
            let mut buf = vec![0u8; count * PKT];
            for x in buf.iter_mut() {
                *x = rng.byte();
            }
            let mut expect = buf.clone();
            for p in 0 .. count {
                let out = scalar_encrypt(&cw, &buf[p * PKT .. (p + 1) * PKT]);
                expect[p * PKT .. (p + 1) * PKT].copy_from_slice(&out);
            }
            CsaBatch::new(&cw).encrypt_in_place(&mut buf);
            assert_eq!(buf, expect, "count {count}");
        }
    }
}
