//! TS layer: descrambles whole 188-byte packets in place with an even/odd control word pair.

use crate::{
    Csa,
    CsaBatch,
};

pub const PACKET_SIZE: usize = 188;

const SYNC_BYTE: u8 = 0x47;
const TSC_MASK: u8 = 0xC0;
const TSC_EVEN: u8 = 0x80;
const TSC_ODD: u8 = 0xC0;

/// Fewer packets of one parity than this go through the scalar path: a batch costs a whole
/// 64-lane word however few lanes are filled, about 3 scalar packets.
const BATCH_MIN: usize = 4;

struct Key {
    csa: Csa,
    batch: CsaBatch,
}

impl Key {
    fn new(cw: &[u8; 8]) -> Self {
        let mut csa = Csa::default();
        csa.set_cw(cw);
        Self {
            csa,
            batch: CsaBatch::new(cw),
        }
    }
}

/// DVB-CSA descrambler for a TS stream.
///
/// A packet is descrambled with the key of its `transport_scrambling_control` parity and its
/// scrambling bits are cleared. Clear packets, packets without the sync byte, the reserved
/// parity `01` and a parity without a key yet pass through untouched. The payload after an
/// adaptation field is descrambled too; a payload under 8 bytes is not scrambled by the
/// standard and only has its bits cleared.
#[derive(Default)]
pub struct Descrambler {
    even: Option<Key>,
    odd: Option<Key>,
    scratch: Vec<u8>,
    /// Payloads of the current parity: byte offset in the input and length
    index: Vec<(usize, usize)>,
    blocks: Vec<u8>,
}

impl Descrambler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_even(&mut self, cw: &[u8; 8]) {
        self.even = Some(Key::new(cw));
    }

    pub fn set_odd(&mut self, cw: &[u8; 8]) {
        self.odd = Some(Key::new(cw));
    }

    /// Descrambles `packets` in place; `packets.len()` must be a multiple of 188. Larger
    /// buffers are faster: the packets of one parity are descrambled as a batch.
    pub fn descramble(&mut self, packets: &mut [u8]) {
        assert!(
            packets.len().is_multiple_of(PACKET_SIZE),
            "buffer length must be a multiple of 188"
        );

        let Self {
            even,
            odd,
            scratch,
            index,
            blocks,
        } = self;
        if let Some(key) = even {
            descramble_parity(packets, TSC_EVEN, key, scratch, index, blocks);
        }
        if let Some(key) = odd {
            descramble_parity(packets, TSC_ODD, key, scratch, index, blocks);
        }
    }
}

fn descramble_parity(
    packets: &mut [u8],
    tsc: u8,
    key: &mut Key,
    scratch: &mut Vec<u8>,
    index: &mut Vec<(usize, usize)>,
    blocks: &mut Vec<u8>,
) {
    index.clear();

    for (i, ts) in packets.chunks_exact_mut(PACKET_SIZE).enumerate() {
        if ts[0] != SYNC_BYTE || ts[3] & TSC_MASK != tsc {
            continue;
        }
        ts[3] &= !TSC_MASK;

        let offset = match ts[3] & 0x30 {
            // payload only
            0x10 => 4,
            // adaptation field and payload
            0x30 => 5 + ts[4] as usize,
            _ => continue,
        };
        if offset + 8 <= PACKET_SIZE {
            index.push((i * PACKET_SIZE + offset, PACKET_SIZE - offset));
        }
    }

    if index.len() < BATCH_MIN {
        for &(at, len) in index.iter() {
            key.csa.decrypt_payload(&mut packets[at .. at + len]);
        }
        return;
    }

    scratch.clear();
    scratch.resize(index.len() * PACKET_SIZE, 0);
    blocks.clear();
    for (slot, &(at, len)) in scratch.chunks_exact_mut(PACKET_SIZE).zip(index.iter()) {
        slot[4 .. 4 + len].copy_from_slice(&packets[at .. at + len]);
        blocks.push((len / 8) as u8);
    }
    key.batch.decrypt_payloads_in_place(scratch, blocks);
    for (slot, &(at, len)) in scratch.chunks_exact(PACKET_SIZE).zip(index.iter()) {
        packets[at .. at + len].copy_from_slice(&slot[4 .. 4 + len]);
    }
}
