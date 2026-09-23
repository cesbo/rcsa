use rcsa::Csa;

include!("../fixtures/dvb_csa.rs");

/// Known-answer test: the reference scrambled packet must decrypt to the
/// reference clear packet under the reference control word.
#[test]
fn decrypts_known_vector() {
    let mut csa = Csa::default();
    csa.set_cw(&CW);

    let mut buffer = vec![0u8; TS_SCRAMBLED.len()];
    csa.decrypt(TS_SCRAMBLED, &mut buffer);

    assert_eq!(buffer, TS_CLEAR);
}

/// The stream state must be reset on every `decrypt`, so re-using a single
/// `Csa` instance for many packets yields the same result each time.
#[test]
fn reuse_across_packets() {
    let mut csa = Csa::default();
    csa.set_cw(&CW);

    let mut buffer = vec![0u8; TS_SCRAMBLED.len()];
    for _ in 0 .. 4 {
        csa.decrypt(TS_SCRAMBLED, &mut buffer);
        assert_eq!(buffer, TS_CLEAR);
    }
}

/// Setting the control word again must fully re-key the descrambler: after
/// decrypting with one CW, a fresh `set_cw` with the correct CW still works.
#[test]
fn rekey_with_set_cw() {
    let mut csa = Csa::default();
    let mut buffer = vec![0u8; TS_SCRAMBLED.len()];

    // Decrypt once with a wrong key -> must not match.
    csa.set_cw(&[0; 8]);
    csa.decrypt(TS_SCRAMBLED, &mut buffer);
    assert_ne!(buffer, TS_CLEAR);

    // Re-key with the correct control word -> must match.
    csa.set_cw(&CW);
    csa.decrypt(TS_SCRAMBLED, &mut buffer);
    assert_eq!(buffer, TS_CLEAR);
}

/// Known-answer test: the reference clear packet must encrypt to the
/// reference scrambled packet under the reference control word.
#[test]
fn encrypts_known_vector() {
    let mut csa = Csa::default();
    csa.set_cw(&CW);

    let mut buffer = vec![0u8; TS_CLEAR.len()];
    csa.encrypt(TS_CLEAR, &mut buffer);

    assert_eq!(buffer, TS_SCRAMBLED);
}

/// `encrypt` and `decrypt` must be exact inverses of each other on all
/// 188 bytes, for random control words and random packets.
#[test]
fn scalar_encrypt_decrypt_round_trip() {
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

    let mut rng = Rng(0x5EED_CAFE_BABE_0001);
    for _ in 0 .. 200 {
        let mut cw = [0u8; 8];
        for x in cw.iter_mut() {
            *x = rng.byte();
        }
        let mut pkt = [0u8; 188];
        for x in pkt.iter_mut() {
            *x = rng.byte();
        }

        let mut csa = Csa::default();
        csa.set_cw(&cw);

        // decrypt(encrypt(pkt)) == pkt
        let mut scrambled = [0u8; 188];
        csa.encrypt(&pkt, &mut scrambled);
        let mut round = [0u8; 188];
        csa.decrypt(&scrambled, &mut round);
        assert_eq!(round, pkt);

        // encrypt(decrypt(pkt)) == pkt
        let mut clear = [0u8; 188];
        csa.decrypt(&pkt, &mut clear);
        let mut round = [0u8; 188];
        csa.encrypt(&clear, &mut round);
        assert_eq!(round, pkt);
    }
}
