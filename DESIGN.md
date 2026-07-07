# DESIGN: Bitsliced / SIMD batch in-place DVB-CSA descrambler

Status: implementation plan (architect). An implementer should follow this verbatim.

Goal: add a batch, in-place, bitsliced descrambler that processes `N = word-width`
packets in lockstep (`N = 64` for `u64`, `N = 256` for AVX2 `__m256i`) **without
touching the existing scalar `Csa` path or its tests**, so the scalar path stays as a
differential oracle.

Everything below is grounded in the current sources:
`src/csa.rs` (scalar `Csa`, `block_decypher`, `stream_cypher*`, `a_group_xor`,
`b_group_xor`, `sum_bit`, `sum_nibble`, `rotate_nibble`), `src/key.rs`
(`expand_key`), `src/bit_u1.rs` (`Bit`), `src/nibble.rs` (`Nibble`),
`src/bs/sbox.rs` (generated `block_sbox` + `BLOCK_PERM_BITS`), and the C reference
`origin/csa.c`.

---

## 0. Key facts established from the sources (correctness anchors)

These are load-bearing; the port must preserve them exactly.

1. **Bit ordering is LSB-first everywhere.** `Bit::new(v) = v & 1`,
   `Nibble(b0,b1,b2,b3)` has `b0` = LSB, `block_sbox` uses `bits[i] = (x>>i)&1` and
   `out[o] = (y>>o)&1`, and `Nibble::unwrap` reassembles `b0 | b1<<1 | ...`. The
   transpose in/out must use the same LSB-first convention.

2. **The block cipher `T` is fully determined by `ib` and `kk` on every
   `block_decypher` call — it does *not* depend on the prior contents of `T`.**
   Proof: the only reads of `T[i+6]`/`T[i+8]` at the early (large-`i`) rounds land in
   `T[56..64]`, which is set to `ib` at the top of the function; every later read
   references an index already written earlier in the same call. This is why the
   existing `reuse_across_packets` test passes even though `decrypt` never resets
   `self.t`. **Consequence for the port:** zero-initialising the bitslice `T` at the
   start of each batch is always correct and matches a fresh `Csa::default()`.

3. **`T` *does* carry across the 23 `block_decypher` calls inside one `decrypt`** only
   through `T[56..64] = ib`; there is no other cross-block `T` dependency. We simply
   run 23 `block_decypher` calls with the running `block` as `ib`, exactly like scalar.

4. **The same control word (CW) is used for all packets in a batch.** Therefore all key
   material is *broadcast* (identical in every lane): the 56 round-key bytes `kk[56]`
   and the 16 CW nibbles `ccw[16]`. Only the ciphertext varies per lane. This means a
   key bit is either "identity" or "per-lane NOT" on a word.

5. **`block` is kept in bitslice form across the whole `decrypt` loop.** After
   `stream_cypher`, `block` holds keystream; then `block ^= next_ct`, so the value fed
   to the next `block_decypher` (`B_{i+1} = KS_i ^ ct_{i+1}`) is produced entirely in
   bitslice. Only the *initial* ciphertext (transpose in) and the *final* plaintext
   (transpose out) cross the byte/bitslice boundary.

6. **No cross-lane movement exists anywhere in the algorithm.** `rotate_nibble`,
   `sum_bit`/`sum_nibble` carries, and the S-box circuits all move bits *within a
   nibble/byte* (i.e. across the 8 bit-words), never across lanes. Bitslicing is
   therefore embarrassingly per-lane: padding/garbage in unused lanes can never corrupt
   a valid lane.

7. **Scalar decrypt control flow to reproduce** (`Csa::decrypt`, `src/csa.rs:599`):
   copy 4-byte header; `block = payload[0..8]`; `stream_init`; `stream_cypher_init(block)`;
   `for i in 0..22 { block_decypher(block); stream_cypher(block); for j in 0..8 { block[j] ^= payload[(i+1)*8+j]; dest[i*8+j] = block[j] ^ T[j]; } }`;
   final `block_decypher(block)`; `dest[176..184] = T[0..8]`.

---

## 1. Module layout (files)

**Unchanged (do not edit):**
- `src/csa.rs` — scalar `Csa`, the differential oracle.
- `src/key.rs` — `expand_key` is `pub(crate)` and is **reused** by the batch key setup.
- `src/bit_u1.rs`, `src/nibble.rs` — scalar `Bit`/`Nibble`, used only by scalar path.
- `tests/decrypt.rs`, `fixtures/dvb_csa.rs`, `benches/decrypt.rs` (benches gets *added*
  to, not rewritten — see §7).
- `src/bs/sbox.rs` — the generated block-S-box circuit (already present and verified).

**New files (all under `src/bs/`):**
- `src/bs/word.rs` — the `Word` trait + `u64` impl + the (generic, reference) transpose
  in/out helpers.
- `src/bs/avx2.rs` — `W256` newtype around `__m256i` and its `Word` impl
  (`#[cfg(target_arch = "x86_64")]`).
- `src/bs/nibble.rs` — generic `Nibble<W>` (4 words) + its `BitXor`.
- `src/bs/stream.rs` — generic stream cipher: `sbox1..sbox7`, `a_group_xor`,
  `b_group_xor`, `sum_bit`, `sum_nibble`, `rotate_nibble`, and `StreamState<W>` with
  `stream_init` / `stream_cypher_init` / `stream_cypher`.
- `src/bs/block.rs` — generic `block_decypher<W>` over the bitslice `T` state.
- `src/bs/batch.rs` — public `CsaBatch`, the generic `descramble<W>` engine, runtime
  AVX2 dispatch, and the batch/transpose glue. Home of the differential/partial unit
  tests.

**Changed files:**
- `src/bs/mod.rs` — declare the new submodules and re-export `CsaBatch`. Change the
  current `#[allow(dead_code)] pub mod sbox;` to a normal `mod sbox;` (still `pub` if
  desired for its tests) plus the new modules.
- `src/lib.rs` — add `pub use bs::CsaBatch;`. Keep `mod bs;`. Leave the existing
  `pub(crate) use bit_u1::Bit; pub(crate) use nibble::Nibble; pub use csa::Csa;`.

Resulting `src/bs/mod.rs`:
```rust
//! Bitslice DVB-CSA descrambler: N packets per machine word, run in lockstep.
mod word;
mod nibble;
mod stream;
mod block;
mod batch;
pub mod sbox;      // keep the generated circuit + its tests public within the crate

#[cfg(target_arch = "x86_64")]
mod avx2;

pub use batch::CsaBatch;
```

---

## 2. The `Word` abstraction (`src/bs/word.rs`)

A `Word` is one machine word holding `LANES` independent packet bits. `block_sbox`
in `src/bs/sbox.rs` is already generic over `T: Copy + BitAnd + BitOr + BitXor + Not`;
`Word` is that bound plus the few extras the batch/transpose glue needs.

```rust
use core::ops::{BitAnd, BitOr, BitXor, Not};

pub trait Word:
    Copy
    + BitAnd<Output = Self>
    + BitOr<Output = Self>
    + BitXor<Output = Self>
    + Not<Output = Self>
{
    /// Packets processed in parallel per word.
    const LANES: usize;
    /// All-zero word (every lane = false).
    const ZERO: Self;
    /// All-one word (every lane = true); equals `!ZERO`.
    const ONES: Self;
    /// Word with only `lane` set (`0 <= lane < LANES`).
    fn lane_mask(lane: usize) -> Self;
    /// Read the bit in `lane`.
    fn get_lane(self, lane: usize) -> bool;
    /// Broadcast one logical bit to every lane (ZERO or ONES).
    #[inline]
    fn splat(bit: bool) -> Self { if bit { Self::ONES } else { Self::ZERO } }
}
```

### 2a. `u64` baseline (always compiled)
```rust
impl Word for u64 {
    const LANES: usize = 64;
    const ZERO: Self = 0;
    const ONES: Self = u64::MAX;
    #[inline] fn lane_mask(l: usize) -> u64 { 1u64 << l }
    #[inline] fn get_lane(self, l: usize) -> bool { (self >> l) & 1 == 1 }
}
```
`u64` already implements the four std bit ops, and for a full 64-lane word `!` is a
correct per-lane NOT. Nothing else required.

### 2b. AVX2 `W256` (`src/bs/avx2.rs`, `#[cfg(target_arch = "x86_64")]`)
```rust
use core::arch::x86_64::*;
#[derive(Copy, Clone)]
pub struct W256(pub __m256i);
```
Implement `BitAnd/BitOr/BitXor` via `_mm256_and_si256` / `_mm256_or_si256` /
`_mm256_xor_si256`, and `Not` via `_mm256_xor_si256(x, _mm256_set1_epi8(-1))`. Each op
body is `#[inline] fn ... { unsafe { intrinsic } }`. `LANES = 256`,
`ZERO = _mm256_setzero_si256()` (build lazily in a `fn` since it is not a `const`;
prefer implementing `ZERO`/`ONES` as `const` via `core::mem::transmute` of `[0u64;4]` /
`[u64::MAX;4]`, or relax `ZERO`/`ONES` from `const` to `fn zero()/ones()` on the trait
if a `const __m256i` proves awkward on 1.94). `lane_mask` / `get_lane`: reinterpret as
`[u64; 4]` (`transmute` or `_mm256_storeu_si256` to an aligned `[u64;4]`) and set/read
bit `lane` in limb `lane/64`, bit `lane%64`.

> **Implementation note (const vs fn):** if a `const __m256i` is inconvenient on the
> pinned toolchain, change the trait to `fn zero() -> Self` / `fn ones() -> Self`
> instead of the `ZERO`/`ONES` consts. This does not affect any call site materially
> (they are all inside generic code). Pick one and keep it consistent; the rest of this
> document uses `ZERO`/`ONES` for brevity.

**Why a newtype:** `__m256i` cannot implement the std bit-op traits directly (orphan
rules / it is a `repr(simd)` type). The AVX2 intrinsics are only sound under an AVX2
target context; correctness of inlining is handled by making the *whole batch function*
`#[target_feature(enable = "avx2")]` (see §5d), so the per-op intrinsics fuse into
`vpand`/`vpor`/`vpxor` there.

### 2c. Transpose helpers (generic, reference implementation) — in `word.rs`
Constants: `const PKT: usize = 188; const HDR: usize = 4; const BLK: usize = 8;`
(23 blocks per payload).

Transpose maps, for one 8-byte block position, an `N`-packets × 64-bits matrix to 64
words × `N` lanes. Word index convention: `word[8*byte + bit]`, LSB-first.

```rust
/// Load block `blk` of `lanes` packets from a contiguous packet buffer into 64 words.
/// `packets` is `count * 188` bytes; only lanes `0..lanes` are read.
pub fn load_block<W: Word>(packets: &[u8], lanes: usize, blk: usize) -> [W; 64] {
    let mut w = [W::ZERO; 64];
    for p in 0..lanes {
        let base = p * PKT + HDR + blk * BLK;
        let m = W::lane_mask(p);
        for byte in 0..8 {
            let v = packets[base + byte];
            for bit in 0..8 {
                if (v >> bit) & 1 == 1 { w[8 * byte + bit] = w[8 * byte + bit] | m; }
            }
        }
    }
    w
}

/// Store 64 words back into block `blk` for lanes `0..lanes` (garbage lanes untouched).
pub fn store_block<W: Word>(w: &[W; 64], packets: &mut [u8], lanes: usize, blk: usize) {
    for p in 0..lanes {
        let base = p * PKT + HDR + blk * BLK;
        for byte in 0..8 {
            let mut v = 0u8;
            for bit in 0..8 {
                if w[8 * byte + bit].get_lane(p) { v |= 1 << bit; }
            }
            packets[base + byte] = v;
        }
    }
}
```
This reference transpose is `O(lanes * 64)` per block; it is deliberately simple and
obviously correct. §7/§8 flag a faster SWAR / `movemask` transpose as a *later,
separately-verified* optimization — it must be gated behind the round-trip test in §6.

---

## 3. Porting the STREAM cipher (`src/bs/stream.rs` + `src/bs/nibble.rs`)

**Decision: introduce word-typed equivalents in `bs`; do NOT genericise the scalar
`Bit`/`Nibble`.** Reasons: scalar `Bit` carries scalar-only semantics (`Not` masks to
the low bit; `unwrap()` and `Shl` exist purely to pack output bits into a byte) and
`csa.rs` must stay byte-for-byte unchanged. The bitslice module gets its own generic
`Nibble<W>` and its own copy of the boolean logic. The duplication is intentional and is
guarded by (a) direct per-S-box exhaustive tests against the reference tables and (b)
the differential test.

### 3a. `Nibble<W>` (`src/bs/nibble.rs`)
```rust
#[derive(Copy, Clone)]
pub struct Nibble<W>(pub W, pub W, pub W, pub W);   // b0=LSB .. b3=MSB

impl<W: Word> Nibble<W> {
    #[inline] pub fn zero() -> Self { Nibble(W::ZERO, W::ZERO, W::ZERO, W::ZERO) }
}
impl<W: Word> core::ops::BitXor for Nibble<W> {
    type Output = Self;
    #[inline] fn bitxor(self, r: Self) -> Self {
        Nibble(self.0 ^ r.0, self.1 ^ r.1, self.2 ^ r.2, self.3 ^ r.3)
    }
}
```

### 3b. Pure-boolean primitives (generic over `W: Word`) — verbatim ports
Port these from `src/csa.rs` line-for-line, replacing `Bit`→`W`, `Nibble`→`Nibble<W>`:
- `sum_bit(z, e, carry, q) -> (W, W)`  (csa.rs:70) — `(e ^ (q & (z ^ carry)), (z & e) | ((z ^ e) & carry))`.
- `sum_nibble(z, e, r, q) -> (Nibble<W>, W)`  (csa.rs:85).
- `rotate_nibble(n, p) -> Nibble<W>`  (csa.rs:105).

All are already branchless (`q`/`p` are per-lane select words), so they bitslice
unchanged. The scalar `Not` masks to low bit but is never used in these three.

### 3c. The seven stream S-boxes as small, individually-testable functions
Extract each S-box's boolean formulas (currently inlined in `a_group_xor`,
csa.rs:243–533) into its own generic function so it can be exhaustively unit-tested:
```rust
#[inline] fn sbox1<W: Word>(a: W, b: W, c: W, d: W, e: W) -> (W /*s1a*/, W /*s1b*/) { ... }
// sbox2..sbox6 likewise return (sNa, sNb)
#[inline] fn sbox7<W: Word>(a: W, b: W, c: W, d: W, e: W) -> (W /*q*/, W /*p*/) { ... }
```
Copy the exact expressions from `csa.rs` (`s1a`,`s1b`, …, and the `self.q`/`self.p`
formulas). The scalar `Not` masks the low bit; the generic `!` complements the full
word. Both are valid per-lane NOT, so the identical text is correct in both worlds.

### 3d. `StreamState<W>` — mirrors the scalar `Csa` stream fields
```rust
pub struct StreamState<W> {
    a: [Nibble<W>; 42],
    b: [Nibble<W>; 42],
    x: Nibble<W>, y: Nibble<W>, z: Nibble<W>,
    d: Nibble<W>, e: Nibble<W>, f: Nibble<W>,
    r: W, p: W, q: W,
}
```
Methods mirror `Csa`:

- `stream_init(&mut self, ccw: &[Nibble<W>; 16])` — port of `Csa::stream_init`
  (csa.rs:205): `a[32..40] = ccw[0..8]`; `b[32..40] = ccw[8..16]`;
  `a[40]=a[41]=b[40]=b[41]=Nibble::zero()`; all scalars/nibbles `x..f = zero`,
  `r=p=q=W::ZERO`.

- `b_group_xor(&mut self, skip: usize)` — port of `Csa::b_group_xor` (csa.rs:226),
  identical index arithmetic and statement order; `sum_nibble` is the generic one.

- `a_group_xor(&mut self, skip: usize)` — port of `Csa::a_group_xor` (csa.rs:243).
  Read the same `a[...]` bits, call `sbox1..sbox6` to build `x`,`y`,`z`
  (`S_GROUP` packing, csa.rs:489–491) and `sbox7` to set `q`,`p`
  (csa.rs:508/517). Preserve the ordering.

- `stream_cypher_init(&mut self, block: &[W; 64])` — port of
  `Csa::stream_cypher_init` (csa.rs:535). Instead of reading bytes, derive the two
  nibbles of byte `i` directly from the transposed block words:
  ```text
  high_i = Nibble(block[8*i+4], block[8*i+5], block[8*i+6], block[8*i+7])   // sb[2i]  = byte>>4
  low_i  = Nibble(block[8*i+0], block[8*i+1], block[8*i+2], block[8*i+3])   // sb[2i+1]= byte&0xF
  ```
  Then for `i in 0..8`, `j in 0..4`, `skip = 31 - i*4 - j`:
  ```text
  tmp_a = if j even { high_i } else { low_i }     //  == sb[j & 1]
  tmp_b = if j even { low_i }  else { high_i }    //  == sb[1 - (j & 1)]
  a[skip] = a[skip+10] ^ x ^ d ^ tmp_a
  b[skip] = rotate_nibble(b[skip+10] ^ y ^ b[skip+7] ^ tmp_b, p)
  b_group_xor(skip); a_group_xor(skip);
  ```
  finish with `a.copy_within(0..10, 32); b.copy_within(0..10, 32);`.
  (This reproduces the scalar high/low-nibble selection derived from
  `sb[j&1]`/`sb[1-(j&1)]` in `origin/csa.c:223–226`.)

- `stream_cypher(&mut self) -> [W; 64]` — port of `Csa::stream_cypher` (csa.rs:571),
  but **emit keystream directly as 64 words** instead of packing bytes. For each
  `i in 0..8`, `j in 0..4`, `skip = 31 - i*4 - j`:
  ```text
  a[skip] = a[skip+10] ^ x
  b[skip] = rotate_nibble(b[skip+10] ^ y ^ b[skip+7], p)
  b_group_xor(skip); a_group_xor(skip)
  ks[8*i + 2*(3-j) + 0] = d.0 ^ d.1     // low  output bit
  ks[8*i + 2*(3-j) + 1] = d.2 ^ d.3     // high output bit
  ```
  then `a.copy_within(0..10, 32); b.copy_within(0..10, 32)` and return `ks`.

  **Derivation of the `2*(3-j)` mapping** (must match scalar exactly): scalar builds
  `tmp = ((d.2^d.3)<<1) | (d.0^d.1)` and does `cb[i] = (cb[i]<<2) | tmp`, so after the
  four `j` iterations byte `i` holds `tmp0<<6 | tmp1<<4 | tmp2<<2 | tmp3`. Hence
  iteration `j` writes byte-bit positions `2*(3-j)` (low = `d0^d1`) and `2*(3-j)+1`
  (high = `d2^d3`). Word index of byte `i` bit `b` is `8*i + b`.

---

## 4. Porting the BLOCK cipher (`src/bs/block.rs`)

State: `T` is 64 bytes → `[[W; 8]; 64]` (`t[byte][bit]`, LSB-first). The round key
`kk[56]` (broadcast, same for all lanes) becomes a mask table
`kk_mask: [[W; 8]; 56]` where `kk_mask[i][b] = W::splat((kk[i] >> b) & 1 == 1)`
(i.e. `W::ONES` where the key bit is 1, else `W::ZERO`). XOR-with-mask realizes the
"identity vs per-lane NOT" the CW selects, branchlessly.

`BLOCK_PERM` is a free relabelling using `BLOCK_PERM_BITS` from `src/bs/sbox.rs`:
`perm[BLOCK_PERM_BITS[k]] = sbox[k]` (zero gates).

Port of `Csa::block_decypher` (csa.rs:184), preserving the threaded `t6` register and
the exact read/write order:
```rust
use crate::bs::sbox::{block_sbox, BLOCK_PERM_BITS};

pub fn block_decypher<W: Word>(
    t: &mut [[W; 8]; 64],
    ib: &[[W; 8]; 8],        // the 8 bitslice bytes of the current block
    kk_mask: &[[W; 8]; 56],
) {
    t[56..64].copy_from_slice(ib);          // T[56..64] = ib
    let mut t6: [W; 8] = t[62];             // == ib[6]

    for i in (0..=55).rev() {
        for b in 0..8 { t6[b] = t6[b] ^ kk_mask[i][b]; }   // t6 ^= kk[i]
        let sbox = block_sbox(t6);                          // one S-box call, 8 words

        // t6 = T[i+6] ^ PERM[sbox];  T[i+6] = t6     (uses the PERMUTED output)
        let mut perm = [W::ZERO; 8];
        for k in 0..8 { perm[BLOCK_PERM_BITS[k]] = sbox[k]; }
        for b in 0..8 { t6[b] = t[i + 6][b] ^ perm[b]; t[i + 6][b] = t6[b]; }

        // sbox_out ^= T[i+8]  (uses the RAW, unpermuted output)
        let mut so = sbox;
        for b in 0..8 { so[b] = so[b] ^ t[i + 8][b]; }

        for b in 0..8 {
            t[i + 4][b] = t[i + 4][b] ^ so[b];
            t[i + 3][b] = t[i + 3][b] ^ so[b];
            t[i + 2][b] = t[i + 2][b] ^ so[b];
            t[i][b]     = so[b];
        }
    }
}
```
Two correctness subtleties to respect (both verified against scalar):
- `t6` is a *threaded register* seeded from `ib[6]` (=`t[62]`), not re-read from
  `t[i+6]` before the key XOR.
- `sbox` feeds `perm` (permuted) for the `t6`/`T[i+6]` update **and** feeds `so`
  (raw) for the `T[i+4..i]` updates. Do not permute `so`.

`block_sbox` is called exactly 56 times per block per batch — this is the whole win: one
663-gate circuit evaluates `N` packets at once.

---

## 5. Batch / transpose glue and PUBLIC API (`src/bs/batch.rs`)

### 5a. Public type (non-generic, so users never touch `Word`)
```rust
pub struct CsaBatch {
    cw:  [u8; 8],
    kk:  [u8; 56],   // from crate::key::expand_key (reused, not reimplemented)
}

impl CsaBatch {
    pub fn new(cw: &[u8; 8]) -> Self { let mut s = Self { cw: *cw, kk: [0; 56] }; s.set_cw(cw); s }
    pub fn set_cw(&mut self, cw: &[u8; 8]) {
        self.cw = *cw;
        crate::key::expand_key(&mut self.kk, cw);   // exact same schedule as scalar
    }

    /// Descramble a contiguous buffer of concatenated 188-byte TS packets in place.
    /// `packets.len()` must be a multiple of 188. Headers (4 bytes) are left untouched;
    /// only the 184-byte payloads are overwritten with plaintext.
    pub fn decrypt_in_place(&mut self, packets: &mut [u8]) {
        debug_assert_eq!(packets.len() % 188, 0);
        #[cfg(target_arch = "x86_64")]
        if std::is_x86_feature_detected!("avx2") {
            // SAFETY: guarded by runtime feature detection.
            unsafe { self.descramble_avx2(packets); }
            return;
        }
        self.descramble::<u64>(packets);
    }
}
```
Optional convenience for non-contiguous callers (mention, implement if needed): a second
method `decrypt_slices(&mut self, payloads: &mut [&mut [u8]])`. The contiguous form is
primary.

### 5b. Key material per `W` (built once per `descramble` call — negligible cost)
```rust
fn kk_mask<W: Word>(kk: &[u8; 56]) -> [[W; 8]; 56] {
    let mut m = [[W::ZERO; 8]; 56];
    for i in 0..56 { for b in 0..8 { m[i][b] = W::splat((kk[i] >> b) & 1 == 1); } }
    m
}
fn ccw_bits<W: Word>(cw: &[u8; 8]) -> [Nibble<W>; 16] {
    // mirror Csa::set_cw (csa.rs:162): high nibble then low nibble of each CW byte,
    // each logical bit broadcast to all lanes via W::splat.
    ...
}
```

### 5c. The generic engine (one lane-group of up to `W::LANES` packets)
```rust
fn descramble<W: Word>(&self, packets: &mut [u8]) {
    let kkm = kk_mask::<W>(&self.kk);
    let ccw = ccw_bits::<W>(&self.cw);
    let total = packets.len() / 188;
    let mut done = 0;
    while done < total {
        let lanes = core::cmp::min(W::LANES, total - done);
        let group = &mut packets[done * 188 .. (done + lanes) * 188];
        descramble_group::<W>(&kkm, &ccw, group, lanes);
        done += lanes;
    }
}

fn descramble_group<W: Word>(
    kkm: &[[W; 8]; 56], ccw: &[Nibble<W>; 16], group: &mut [u8], lanes: usize,
) {
    // 1. transpose the whole payload in (23 blocks) — decouples reads from writes,
    //    so in-place writes can never alias a not-yet-read ciphertext block.
    let mut ct = [[W::ZERO; 64]; 23];
    for k in 0..23 { ct[k] = load_block::<W>(group, lanes, k); }

    // 2. block-cipher state (zero-init is correct; see fact #2).
    let mut t = [[W::ZERO; 8]; 64];

    // 3. stream init from ciphertext block 0 (the IV).
    let mut st = StreamState::<W>::new();
    st.stream_init(ccw);
    st.stream_cypher_init(&ct[0]);

    // 4. running block, kept in bitslice; starts as ct block 0.
    let mut block = split_to_bytes(&ct[0]);   // [[W;8];8] view of the 64 words

    for i in 0..22 {
        block_decypher::<W>(&mut t, &block, kkm);   // updates t
        let ks = st.stream_cypher();                 // 64 keystream words
        // block = ks ^ ct[i+1]  ;  plaintext_i = block ^ T[0..8]
        let mut pt = [W::ZERO; 64];
        for byte in 0..8 { for bit in 0..8 {
            let w = 8 * byte + bit;
            let nb = ks[w] ^ ct[i + 1][w];      // B_{i+1}
            block[byte][bit] = nb;
            pt[w] = nb ^ t[byte][bit];          // dest block i, byte, bit
        }}
        store_block::<W>(&pt, group, lanes, i);
    }

    block_decypher::<W>(&mut t, &block, kkm);   // final block
    // dest block 22 = T[0..8]
    let mut last = [W::ZERO; 64];
    for byte in 0..8 { for bit in 0..8 { last[8*byte+bit] = t[byte][bit]; } }
    store_block::<W>(&last, group, lanes, 22);
}
```
Helper `split_to_bytes(&[W;64]) -> [[W;8];8]` just regroups the 64 words into 8 bytes ×
8 bits (used to feed `block_decypher`'s `ib`). Keep `block` as `[[W;8];8]` throughout.

**(a) Batch of N packets** — the `while done < total` loop chunks by `W::LANES`.
**(b) Contiguous layout** — `load_block`/`store_block` stride by 188 and skip the 4-byte
header; headers are never written (in place ⇒ already correct).
**(c) In place** — the up-front full-payload transpose means every ciphertext block is
read into `ct[..]` before any plaintext is written back, so overwriting payload block `i`
cannot clobber a ciphertext block still needed later. (A block-streaming variant is a
valid later optimization but must preserve "read `ct[i+1]` before writing block `i+1`".)
**Remainder (`< N` packets)** — `lanes < W::LANES`: unused lanes stay `W::ZERO`, compute
garbage that `store_block` never writes (it loops `0..lanes`). No padding needed; fact #6
guarantees valid lanes are unaffected. No out-of-bounds because `load`/`store` bound by
`lanes` and `group` is sliced to exactly `lanes*188`.

### 5d. AVX2 dispatch wrapper
```rust
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn descramble_avx2(&self, packets: &mut [u8]) {
    self.descramble::<W256>(packets);   // monomorphized under an AVX2 context
}
```
Putting `#[target_feature(enable = "avx2")]` on the outer function guarantees the
`W256` intrinsics fuse to `vpand`/`vpor`/`vpxor` throughout the monomorphized call tree.
`decrypt_in_place` calls it only after `is_x86_feature_detected!("avx2")` (sound). On
non-x86 or non-AVX2 hardware, the `u64` path runs.

---

## 6. Correctness gates (in order — each must pass before the next is built)

1. **(a) S-box circuit 256/256.** Already present: the `#[cfg(test)]` tests in
   `src/bs/sbox.rs` (`block_sbox_matches_table`, `block_perm_bits_matches_table`).
   `cargo test` must keep these green; do not modify `sbox.rs`.

2. **Transpose round-trip (new unit test in `word.rs`).** For random buffers of `k`
   packets (`k` in `{1, 7, 63, 64}` for `u64`; also `{255,256}` for `W256`),
   `store_block(load_block(buf))` reproduces the payload bytes exactly for every lane and
   block. Locks the LSB-first byte/bit convention. *(Also add a `W256` variant guarded by
   `is_x86_feature_detected!("avx2")` or `#[cfg(target_feature="avx2")]`.)*

3. **Stream S-box exhaustive (new unit tests in `stream.rs`).** Embed the reference
   tables from `origin/csa.c` (`sbox1..sbox6`, `sbox7p`/`sbox7q`, lines 138–160).
   Instantiate the generic `sbox1..sbox7` with `W = u8`, broadcasting each 1-bit input
   to `0x00`/`0xFF` (same trick as `sbox.rs`). For all 32 input combinations
   (`A_GROUP`/`S_GROUP` packing order per `origin/csa.c:57–97`), assert the two output
   words equal the table entries. This locks the bitslice stream logic to the reference
   independently of `csa.rs`.

4. **(b) Existing KAT still passes.** `tests/decrypt.rs` (`decrypts_known_vector`,
   `reuse_across_packets`, `rekey_with_set_cw`) is untouched and must stay green
   (`csa.rs` unchanged).

5. **Batch KAT (new unit test in `batch.rs`).** Build a buffer of `N` copies of
   `TS_SCRAMBLED` (use `include!("../../fixtures/dvb_csa.rs")` — adjust the relative path
   for `src/bs/`), `CsaBatch::new(&CW)`, `decrypt_in_place`, assert **every** 188-byte
   lane equals `TS_CLEAR`. Run it once forcing `descramble::<u64>` and once forcing
   `descramble::<W256>` (guarded by feature detection).

6. **(c) Differential test (new unit test in `batch.rs`) — the main gate.** For many
   iterations (e.g. 200): pick a random `[u8;8]` CW and `count` random 188-byte packets
   (`count` random in `1..=2*LANES`). Compute the oracle with a **fresh
   `Csa::default()`** per packet (`set_cw(cw)`, `decrypt(src, &mut dst)`), and the batch
   with `CsaBatch::new(&cw).decrypt_in_place(&mut buf_copy)`. Assert every packet's 188
   bytes match byte-for-byte on every lane. Run the batch side once via `descramble::<u64>`
   and once via `descramble::<W256>` (feature-gated). Use a small deterministic PRNG
   (e.g. a hand-rolled xorshift/SplitMix64 seeded from a constant) so no new dependency is
   added and failures reproduce.

7. **(d) Partial final batch (new unit test in `batch.rs`).** With a fixed CW, run
   `decrypt_in_place` on buffers of `1`, `3`, `N-1`, `N`, `N+1`, and `2N+3` packets
   (random contents) and compare each packet against the scalar oracle. This exercises
   the remainder path (unused lanes) and the multi-group loop. Do it for both `u64`
   (`N=64`) and `W256` (`N=256`).

For gates 5–7 to force a specific backend from unit tests, expose crate-internal
`pub(crate) fn descramble_u64`/`descramble_avx2` shims (or make `descramble::<W>`
`pub(crate)`); these live in-crate so `#[cfg(test)] mod tests` in `batch.rs` can call
them and also reach `crate::Csa`. The public API stays just `CsaBatch`.

---

## 7. Benchmarks (`benches/decrypt.rs`, extend — do not rewrite)

Keep the existing `decrypt_packet` scalar benchmark. Add batch benchmarks that report
throughput over the payload times the batch size so numbers are comparable:

- Group `csa`, keep `Throughput::Bytes(184)` for the scalar single-packet bench.
- New group `csa_batch`. For each backend that is available, prepare a contiguous buffer
  of `N` copies of `TS_SCRAMBLED` and set `group.throughput(Throughput::Bytes(184 * N))`.
  - `batch_u64`: force `descramble::<u64>` (`N = 64`). Expose a `#[doc(hidden)]`
    `CsaBatch::decrypt_in_place_u64` (or a bench-only crate feature) so the bench can pin
    the backend; otherwise `decrypt_in_place` already selects AVX2 at runtime.
  - `batch_avx2`: only register if `is_x86_feature_detected!("avx2")` (`N = 256`).
  - `bench_function` body: `b.iter(|| batch.decrypt_in_place(black_box(&mut buf)))`
    (re-fill or accept in-place mutation — since output is deterministic, decrypting the
    already-decrypted buffer changes throughput semantics; instead clone a fresh scrambled
    buffer per iteration via `b.iter_batched`/`iter_with_setup`, or keep a scratch copy).
- Report and compare: scalar bytes/s vs `batch_u64` bytes/s vs `batch_avx2` bytes/s.

Because the naive transpose (§2c) is `O(lanes*64)` per block, expect the first
measurements to be transpose-bound; that is fine for the first landing. The optimized
transpose (SWAR 8×8 for `u64`; `_mm256_movemask_epi8` over 8 shifted copies for `W256`)
is a follow-up whose only gate is the round-trip test #2 (behavior identical, speed only).

---

## 8. Risks and the exact recommended implementation ORDER

### Risks (and mitigations)
- **Boolean transcription errors** porting the 7 stream S-boxes / `block_decypher`.
  → per-S-box exhaustive table tests (#3) + differential test (#6). These catch any
  single-bit divergence immediately.
- **Bit-order / transpose confusion (LSB vs MSB).** → round-trip test (#2) + differential.
- **`BLOCK_PERM` applied to the wrong copy** (permuted vs raw `sbox_out`). → the explicit
  `perm` vs `so` split in §4, backed by the differential test on the block cipher.
- **`t6` register threading / read-write ordering** in `block_decypher`. → follow §4
  exactly; differential test guards it.
- **Stream keystream bit-position mapping** (`2*(3-j)`). → the derivation in §3d plus the
  batch KAT (#5) which fails loudly on any packing error.
- **AVX2 soundness / inlining.** Intrinsics only sound under an AVX2 context; the whole
  batch is `#[target_feature(enable="avx2")]` and dispatched behind
  `is_x86_feature_detected!`. → both backends are run through the *same* differential and
  KAT gates.
- **`const __m256i`** for `ZERO`/`ONES` may be awkward on the pinned 1.94 toolchain.
  → fall back to `fn zero()/ones()` on the trait (noted in §2b); no call-site impact.
- **In-place aliasing** when writing plaintext over ciphertext still needed. → the
  up-front full-payload transpose (§5c) removes the hazard entirely for v1.
- **Partial-batch garbage lanes.** → fact #6 (no cross-lane movement) + `load`/`store`
  bounded by `lanes`; partial test (#7) confirms.
- **Naive transpose is slow.** → correctness first; optimized transpose is a gated
  follow-up (#2 is its only correctness gate).

### Implementation order (keep `cargo test` green at every step)
1. **`Word` + `u64` impl + transpose (`word.rs`).** Add round-trip unit test (#2).
   `cargo test` green.
2. **`Nibble<W>` (`nibble.rs`) + stream primitives + `sbox1..sbox7` (`stream.rs`).** Add
   exhaustive S-box tests vs the C tables (#3). Green.
3. **`StreamState<W>`** (`stream_init`/`stream_cypher_init`/`stream_cypher`) in
   `stream.rs`. No standalone test yet (covered by #5/#6); just compiles. Green.
4. **`block_decypher<W>` (`block.rs`).** Optional: a single-lane unit test comparing
   against `Csa::block_decypher` on random `ib`/`kk` (make a tiny in-crate harness), else
   rely on #6. Green.
5. **`CsaBatch` + `descramble::<u64>` + glue (`batch.rs`).** Wire `mod.rs`/`lib.rs`. Add
   batch KAT (#5, u64), differential (#6, u64), partial (#7, u64). Green.
6. **AVX2 `W256` (`avx2.rs`) + `descramble_avx2` dispatch.** Re-run #2/#5/#6/#7 on the
   `W256` backend (feature-gated). Green.
7. **Benchmarks (§7)** and, separately, the **optimized transpose** (gated only by the
   round-trip test #2). Green.

At every step the scalar `Csa` and `tests/decrypt.rs` are untouched, so gate (b) can
never regress; new modules are additive behind `mod bs;`.
