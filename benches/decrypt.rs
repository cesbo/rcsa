use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

use csa::Csa;

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

criterion_group!(benches, bench_decrypt);
criterion_main!(benches);
