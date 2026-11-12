use rcsa::{
    Csa,
    Descrambler,
    PACKET_SIZE,
    Parity,
    Scrambler,
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

/// Scrambled payloads with and without a trailing partial block match libdvbcsa.
#[test]
fn scramble_payload_vectors() {
    let mut csa = Csa::default();
    csa.set_cw(&PAYLOAD_CW);

    for (clear, scrambled) in PAYLOADS {
        let mut data = clear.to_vec();
        csa.encrypt_payload(&mut data);
        assert_eq!(&data, scrambled, "payload of {} bytes", clear.len());
    }
}

/// A clear packet around a fixture payload and its scrambled form with even parity: payload
/// only for 184 bytes, after an adaptation field otherwise.
fn fixture_packet(clear: &[u8], scrambled: &[u8]) -> (Vec<u8>, Vec<u8>) {
    if clear.len() < 184 {
        let (scrambled, clear) = af_packet(0x80, scrambled, clear);
        return (clear, scrambled);
    }
    let packet = |tsc: u8, payload: &[u8]| [&[0x47, 0x01, 0x00, tsc | 0x10], payload].concat();
    (packet(0x00, clear), packet(0x80, scrambled))
}

/// Packets of every fixture length match libdvbcsa, on the scalar path (few packets) and on
/// every batch width.
#[test]
fn scramble_matches_oracle() {
    let (full, short): (Vec<_>, Vec<_>) = PAYLOADS.iter().partition(|(c, _)| c.len() == 184);

    for count in [1, 3, 40, 64, 150, 300] {
        let mut input = Vec::new();
        let mut expected = Vec::new();
        for i in 0 .. count {
            for (clear, scrambled) in [full[i % full.len()], short[i % short.len()]] {
                let (clear, scrambled) = fixture_packet(clear, scrambled);
                input.extend(clear);
                expected.extend(scrambled);
            }
        }

        let mut s = Scrambler::new();
        s.set_even(&PAYLOAD_CW);
        s.set_odd(&CW);
        s.scramble(&mut input, Parity::Even);
        assert!(input == expected, "{count} packets");
    }

    let mut s = Scrambler::new();
    s.set_odd(&CW);
    for count in [1, 300] {
        let mut input = full_clear().repeat(count);
        s.scramble(&mut input, Parity::Odd);
        assert!(input == full_packet(0xC0).repeat(count), "{count} packets");
    }
}

const PSI_PID: u8 = 0x11;

/// Clear PSI, adaptation-field-only packets and payloads of every length from 0 to 184.
fn mixed_stream() -> Vec<u8> {
    let mut seed = 0x2545_F491u32;
    let mut byte = move || {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        (seed >> 24) as u8
    };

    let mut out = Vec::new();
    for len in 0 ..= 184usize {
        if len < 184 {
            let af_len = 183 - len;
            out.extend([0x47, 0x01, 0x00, 0x30, af_len as u8]);
            out.extend(std::iter::repeat_n(0xFF, af_len));
        } else {
            out.extend([0x47, 0x01, 0x00, 0x10]);
        }
        out.extend(std::iter::repeat_with(&mut byte).take(len));

        if len % 5 == 0 {
            out.extend([0x47, 0x00, PSI_PID, 0x10]);
            out.extend(std::iter::repeat_with(&mut byte).take(184));
        }
        if len % 7 == 0 {
            out.extend([0x47, 0x01, 0x00, 0x20, 183]);
            out.extend(std::iter::repeat_n(0xFF, 183));
        }
        for _ in 0 .. len % 9 {
            out.extend([0x47, 0x01, 0x00, 0x10]);
            out.extend(std::iter::repeat_with(&mut byte).take(184));
        }
    }
    out
}

/// The caller keeps PSI clear by scrambling only the runs between PSI packets; the parity
/// switches on every run. The descrambler restores the stream.
#[test]
fn scramble_round_trip() {
    let clear = mixed_stream();
    let mut stream = clear.clone();

    let mut s = Scrambler::new();
    s.set_even(&PAYLOAD_CW);
    s.set_odd(&CW);
    let mut parity = Parity::Even;
    let is_psi = |ts: &[u8]| ts[2] == PSI_PID;
    let mut rest = &mut stream[..];
    while !rest.is_empty() {
        let psi = is_psi(rest);
        let run = rest
            .chunks_exact(PACKET_SIZE)
            .take_while(|ts| is_psi(ts) == psi)
            .count();
        let (head, tail) = rest.split_at_mut(run * PACKET_SIZE);
        if !psi {
            s.scramble(head, parity);
            parity = match parity {
                Parity::Even => Parity::Odd,
                Parity::Odd => Parity::Even,
            };
        }
        rest = tail;
    }

    let mut tsc = [0usize; 4];
    for (ts, orig) in stream
        .chunks_exact(PACKET_SIZE)
        .zip(clear.chunks_exact(PACKET_SIZE))
    {
        let payload = match orig[3] & 0x30 {
            0x10 => 184,
            0x30 => 183 - orig[4] as usize,
            _ => 0,
        };
        if orig[2] == PSI_PID || payload == 0 {
            assert_eq!(ts, orig);
            continue;
        }
        tsc[(ts[3] >> 6) as usize] += 1;
        assert_eq!(ts[3] & 0x3F, orig[3]);
        assert_eq!(
            ts[.. PACKET_SIZE - payload][4 ..],
            orig[.. PACKET_SIZE - payload][4 ..]
        );
        let scrambled = ts[PACKET_SIZE - payload ..] != orig[PACKET_SIZE - payload ..];
        assert_eq!(scrambled, payload >= 8, "payload of {payload} bytes");
    }
    assert!(tsc[0] == 0 && tsc[1] == 0 && tsc[2] > 100 && tsc[3] > 100);

    let mut d = Descrambler::new();
    d.set_even(&PAYLOAD_CW);
    d.set_odd(&CW);
    d.descramble(&mut stream);
    assert!(stream == clear);
}

/// A lost sync byte, scrambled packets, packets without a payload and a broken adaptation
/// field length pass through untouched, and so does everything without a key.
#[test]
fn scramble_passthrough() {
    let mut no_sync = full_clear();
    no_sync[0] = 0x00;
    let af = |afc: u8, len: u8| {
        let mut ts = vec![0x47, 0x01, 0x00, afc, len];
        ts.resize(PACKET_SIZE, 0xFF);
        ts
    };

    let mut input = [
        no_sync,
        full_packet(0x40),
        full_packet(0x80),
        full_packet(0xC0),
        af(0x00, 0),
        af(0x20, 183),
        af(0x30, 183),
        af(0x30, 255),
    ]
    .concat();
    let expected = input.clone();

    let mut s = Scrambler::new();
    s.set_even(&CW);
    s.scramble(&mut input, Parity::Even);
    assert!(input == expected);

    let mut input = full_clear();
    s.scramble(&mut input, Parity::Odd);
    assert_eq!(input, full_clear());
}

/// A payload under 8 bytes stays clear and only gets the scrambling bits.
#[test]
fn scramble_short_payload() {
    let mut s = Scrambler::new();
    s.set_odd(&CW);

    for len in 1 .. 8 {
        let (_, clear) = af_packet(0x00, &[0xA5; 8][.. len], &[0xA5; 8][.. len]);
        let mut ts = clear.clone();
        s.scramble(&mut ts, Parity::Odd);
        assert_eq!(ts[3], 0xF0);
        ts[3] = 0x30;
        assert_eq!(ts, clear);
    }
}
