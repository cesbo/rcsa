use std::hint::black_box;

use criterion::{
    Criterion,
    Throughput,
    criterion_group,
    criterion_main,
};
use rcsa::{
    Csa,
    CsaBatch,
    Descrambler,
    PACKET_SIZE,
};

include!("../fixtures/dvb_csa.rs");

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("csa");

    // Only the 184-byte payload is scrambled; the 4-byte TS header is copied
    // verbatim. Reporting throughput over the payload makes the numbers
    // directly comparable across implementations.
    group.throughput(Throughput::Bytes(184));

    group.bench_function("decrypt_packet", |b| {
        let mut csa = Csa::default();
        csa.set_cw(&CW);
        let mut buffer = vec![0u8; TS_SCRAMBLED.len()];

        b.iter(|| {
            csa.decrypt(black_box(TS_SCRAMBLED), black_box(&mut buffer));
        });
    });

    group.finish();
}

// Batch throughput. The descrambler is data-independent (same operations
// regardless of payload contents), so decrypting the buffer in place
// repeatedly measures steady-state throughput correctly.
fn bench_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("csa_batch");

    let batch = CsaBatch::new(&CW);

    // 64-wide portable backend.
    {
        let n = 64usize;
        let mut buf = TS_SCRAMBLED.repeat(n);
        group.throughput(Throughput::Bytes(184 * n as u64));
        group.bench_function("batch_u64_x64", |b| {
            b.iter(|| batch.decrypt_in_place_u64(black_box(&mut buf)));
        });
    }

    // 256-wide AVX2 backend (only if available at runtime).
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        let n = 256usize;
        let mut buf = TS_SCRAMBLED.repeat(n);
        group.throughput(Throughput::Bytes(184 * n as u64));
        group.bench_function("batch_avx2_x256", |b| {
            b.iter(|| batch.decrypt_in_place_avx2(black_box(&mut buf)));
        });
    }

    group.finish();
}

// TS layer on a stream like a real channel: 2% of the packets carry an adaptation field.
// The scrambling bits are restored before every pass, which the raw batch skips.
fn bench_ts(c: &mut Criterion) {
    let mut group = c.benchmark_group("csa_ts");

    let n = 1024usize;
    let mut buf = TS_SCRAMBLED.repeat(n);
    for i in (0 .. n).step_by(50) {
        let ts = &mut buf[i * PACKET_SIZE .. (i + 1) * PACKET_SIZE];
        ts[3] |= 0x30;
        ts[4] = 7;
    }
    let mut d = Descrambler::new();
    d.set_odd(&CW);

    group.throughput(Throughput::Bytes(184 * n as u64));
    group.bench_function("descramble_x1024", |b| {
        b.iter(|| {
            for ts in buf.chunks_exact_mut(PACKET_SIZE) {
                ts[3] |= 0xC0;
            }
            d.descramble(black_box(&mut buf));
        });
    });

    let batch = CsaBatch::new(&CW);
    let mut raw = TS_SCRAMBLED.repeat(n);
    group.bench_function("batch_x1024", |b| {
        b.iter(|| batch.decrypt_in_place(black_box(&mut raw)));
    });

    group.finish();
}

criterion_group!(benches, bench_decrypt, bench_batch, bench_ts);
criterion_main!(benches);
