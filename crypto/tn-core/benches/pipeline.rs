use criterion::{criterion_group, criterion_main, Criterion};

fn placeholder(c: &mut Criterion) {
    c.bench_function("placeholder", |b| b.iter(|| ()));
}

criterion_group!(benches, placeholder);
criterion_main!(benches);
