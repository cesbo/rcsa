use rcsa::{
    Csa,
    Descrambler,
    PACKET_SIZE,
};

include!("../fixtures/dvb_csa.rs");
include!("../fixtures/csa_payloads.rs");

/// Payloads with and without a trailing partial block match libdvbcsa.
#[test]
fn payload_vectors() {
    let mut csa = Csa::default();
    csa.set_cw(&PAYLOAD_CW);

    for (clear, scrambled) in PAYLOADS {
        let mut data = scrambled.to_vec();
        csa.decrypt_payload(&mut data);
        assert_eq!(&data, clear, "payload of {} bytes", clear.len());
    }
}

/// A payload under 8 bytes is not scrambled by the standard.
#[test]
fn short_payload_untouched() {
    let mut csa = Csa::default();
    csa.set_cw(&PAYLOAD_CW);

    for len in 0 .. 8 {
        let mut data = vec![0xA5; len];
        csa.decrypt_payload(&mut data);
        assert_eq!(data, vec![0xA5; len]);
    }
}

/// `TS_SCRAMBLED` with the given scrambling bits (payload only).
fn full_packet(tsc: u8) -> Vec<u8> {
    let mut ts = TS_SCRAMBLED.to_vec();
    ts[3] = (ts[3] & 0x3F) | tsc;
    ts
}

/// `TS_CLEAR` as the descrambler leaves it: scrambling bits cleared.
fn full_clear() -> Vec<u8> {
    let mut ts = TS_CLEAR.to_vec();
    ts[3] &= 0x3F;
    ts
}

/// A packet with an adaptation field in front of `payload`, and its descrambled form.
fn af_packet(tsc: u8, payload: &[u8], clear: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let af_len = PACKET_SIZE - 5 - payload.len();
    let mut ts = vec![0x47, 0x01, 0x00, tsc | 0x30, af_len as u8];
    ts.extend(std::iter::repeat_n(0xFF, af_len));
    let mut expected = ts.clone();
    expected[3] &= 0x3F;
    ts.extend_from_slice(payload);
    expected.extend_from_slice(clear);
    (ts, expected)
}

/// Even and odd keys, full payloads and payloads of every fixture length after an adaptation
/// field, on the scalar path (few packets) and on every batch width.
#[test]
fn descramble_mixed_stream() {
    let short: Vec<_> = PAYLOADS.iter().filter(|(c, _)| c.len() < 184).collect();

    for count in [1, 3, 40, 64, 150, 300] {
        let mut input = Vec::new();
        let mut expected = Vec::new();
        for i in 0 .. count {
            input.extend(full_packet(0xC0));
            expected.extend(full_clear());

            let (clear, scrambled) = short[i % short.len()];
            let (ts, clear) = af_packet(0x80, scrambled, clear);
            input.extend(ts);
            expected.extend(clear);
        }

        let mut d = Descrambler::new();
        d.set_odd(&CW);
        d.set_even(&PAYLOAD_CW);
        d.descramble(&mut input);
        assert!(input == expected, "{count} packets");
    }
}

/// Clear packets, the reserved parity, a lost sync byte and a parity without a key pass
/// through untouched; a scrambled packet without payload only loses its bits.
#[test]
fn passthrough() {
    let mut clear = TS_SCRAMBLED.to_vec();
    clear[3] &= 0x3F;
    let reserved = full_packet(0x40);
    let mut no_sync = full_packet(0xC0);
    no_sync[0] = 0x00;
    let even = full_packet(0x80);
    let mut af_only = vec![0x47, 0x01, 0x00, 0xE0, 183];
    af_only.resize(PACKET_SIZE, 0xFF);

    let mut input = [clear, reserved, no_sync, even, af_only].concat();
    let mut expected = input.clone();
    expected[4 * PACKET_SIZE + 3] = 0x20;

    let mut d = Descrambler::new();
    d.set_odd(&CW);
    d.descramble(&mut input);
    assert!(input == expected);
}

/// A new key replaces the old one.
#[test]
fn rekey() {
    let mut d = Descrambler::new();
    d.set_odd(&[0; 8]);
    d.set_odd(&CW);

    let mut ts = full_packet(0xC0);
    d.descramble(&mut ts);
    assert_eq!(ts, full_clear());
}
