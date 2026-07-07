//! Bitslice / SIMD DVB-CSA descrambler: `N` packets per machine word, run in
//! lockstep. See [`CsaBatch`] for the public batch API.

mod block;
mod nibble;
pub mod sbox;
mod stream;
mod word;

mod batch;

#[cfg(target_arch = "x86_64")]
mod avx2;

pub use batch::CsaBatch;
