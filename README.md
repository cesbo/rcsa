# rcsa

Pure Rust DVB Common Scrambling Algorithm (DVB-CSA) for MPEG transport streams.

- `Descrambler`: descrambles 188-byte TS packets in place with an even/odd control
  word pair. Payloads after an adaptation field and trailing partial blocks are
  handled; descrambled packets get their scrambling bits cleared.
- `CsaBatch`: bitsliced batch of full-payload packets, 64 lanes (`u64`), 128 lanes
  (SSE2, NEON) or 256 lanes (AVX2, detected at runtime). Decrypt and encrypt.
- `Csa`: one packet at a time, any payload length.

No dependencies; `unsafe` only in the SIMD backends and their dispatch.

## Usage

```rust
use rcsa::Descrambler;

let mut descrambler = Descrambler::new();
descrambler.set_even(&cw[.. 8].try_into()?);
descrambler.set_odd(&cw[8 ..].try_into()?);

// a whole number of 188-byte packets; larger buffers are faster
descrambler.descramble(&mut packets);
```

When a new control word takes effect is up to the caller: `set_even`/`set_odd`
replace the key immediately.

## Performance

Descrambling real SD and HD channels, one core of a Xeon E5-2660 v3 (Haswell),
buffers of 1024-4096 packets, payload Mbit/s. FFdecsa and libdvbcsa built with
`-O3 -msse2`, rcsa with the default target (AVX2 picked at runtime):

| | Mbit/s |
|---|---:|
| rcsa | 1230-1280 |
| FFdecsa | 1070-1090 |
| libdvbcsa | 750-765 |

Without AVX2 (SSE2) rcsa does about 980 Mbit/s on the same CPU.
