use csa::Csa;

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
