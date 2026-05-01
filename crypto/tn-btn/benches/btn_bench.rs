//! Criterion benchmarks for `btn`.
//!
//! Run with: `cargo bench` (full suite) or
//! `cargo bench --bench btn_bench -- <filter>` (subset).
//!
//! Groups:
//! - `setup` — one-shot PublisherState::setup_with_seed.
//! - `mint` — per-kit cost.
//! - `encrypt/r=N` — encrypt() at various revocation counts. Dominant
//!   hot path for publishers.
//! - `decrypt/r=N` — decrypt() at various revocation counts. Reader
//!   side; should be much faster than encrypt because only ONE cover
//!   entry needs to be processed per decrypt, regardless of how many
//!   revoked there are.
//! - `wire` — Ciphertext + ReaderKit to_bytes / from_bytes.
//!
//! Baseline numbers to track over time live in `benches/README.md`
//! (not yet written). After the first full run, pin numbers for
//! encrypt at r=0, r=10, r=100 as regression anchors.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tn_btn::{config::TREE_HEIGHT, Ciphertext, Config, PublisherState, ReaderKit};

const SEED: [u8; 32] = [0x5Bu8; 32];
const PAYLOAD: &[u8; 128] = &[0xAAu8; 128];

fn bench_setup(c: &mut Criterion) {
    c.bench_function("setup", |b| {
        b.iter(|| {
            let s = PublisherState::setup_with_seed(Config, black_box(SEED)).unwrap();
            black_box(s);
        });
    });
}

fn bench_mint(c: &mut Criterion) {
    // Amortized per-mint cost. Set up once, mint repeatedly.
    c.bench_function("mint", |b| {
        let mut s = PublisherState::setup_with_seed(Config, SEED).unwrap();
        b.iter(|| {
            // Reset state if we approach tree exhaustion. MAX_LEAVES is
            // config-dependent so we compare against a fraction of it.
            if (s.issued_count() + s.revoked_count()) as u64 >= tn_btn::config::MAX_LEAVES - 8 {
                s = PublisherState::setup_with_seed(Config, SEED).unwrap();
            }
            let k = s.mint().unwrap();
            black_box(k);
        });
    });
}

// Revocation counts to benchmark. Bench must leave at least one unrevoked
// kit (so the decrypt bench has a valid reader), so we skip any r >= mint_count
// at runtime. That way these arrays stay valid across TREE_HEIGHT changes
// without tripping the bench over.
const ENCRYPT_REVOCATION_COUNTS: &[usize] = &[0, 1, 5, 10, 25, 50, 100, 250, 500];
const DECRYPT_REVOCATION_COUNTS: &[usize] = &[0, 1, 10, 100, 500];

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt");
    group.throughput(Throughput::Bytes(PAYLOAD.len() as u64));

    let mint_count = (tn_btn::config::MAX_LEAVES - 1) as usize;
    for &r in ENCRYPT_REVOCATION_COUNTS
        .iter()
        .filter(|&&r| r < mint_count)
    {
        group.bench_with_input(BenchmarkId::from_parameter(r), &r, |b, &r| {
            let mut s = PublisherState::setup_with_seed(Config, SEED).unwrap();
            // Mint MAX_LEAVES-1 then revoke r of them. survivors = leaves-1-r.
            let kits: Vec<_> = (0..mint_count).map(|_| s.mint().unwrap()).collect();
            for kit in kits.iter().take(r) {
                s.revoke(kit).unwrap();
            }
            b.iter(|| {
                let ct = s.encrypt(black_box(PAYLOAD)).unwrap();
                black_box(ct);
            });
        });
    }
    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt");
    group.throughput(Throughput::Bytes(PAYLOAD.len() as u64));

    let mint_count = (tn_btn::config::MAX_LEAVES - 1) as usize;
    for &r in DECRYPT_REVOCATION_COUNTS
        .iter()
        .filter(|&&r| r < mint_count)
    {
        group.bench_with_input(BenchmarkId::from_parameter(r), &r, |b, &r| {
            let mut s = PublisherState::setup_with_seed(Config, SEED).unwrap();
            let kits: Vec<_> = (0..mint_count).map(|_| s.mint().unwrap()).collect();
            for kit in kits.iter().take(r) {
                s.revoke(kit).unwrap();
            }
            // Pick a non-revoked reader (kit at index r — revocations are 0..r).
            let reader = &kits[r];
            let ct = s.encrypt(PAYLOAD).unwrap();
            b.iter(|| {
                let pt = reader.decrypt(black_box(&ct)).unwrap();
                black_box(pt);
            });
        });
    }
    group.finish();
}

fn bench_wire_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("wire");
    let mut s = PublisherState::setup_with_seed(Config, SEED).unwrap();
    let kit = s.mint().unwrap();
    let _ = s.mint().unwrap();
    // r=0 and r=10 ciphertexts for bench.
    let ct_r0 = s.encrypt(PAYLOAD).unwrap();
    for kit in (0..10).map(|_| s.mint().unwrap()).collect::<Vec<_>>() {
        s.revoke(&kit).unwrap();
    }
    let ct_r10 = s.encrypt(PAYLOAD).unwrap();

    group.bench_function("ciphertext_to_bytes_r0", |b| {
        b.iter(|| black_box(ct_r0.to_bytes()));
    });
    group.bench_function("ciphertext_to_bytes_r10", |b| {
        b.iter(|| black_box(ct_r10.to_bytes()));
    });
    let bytes_r0 = ct_r0.to_bytes();
    let bytes_r10 = ct_r10.to_bytes();
    group.bench_function("ciphertext_from_bytes_r0", |b| {
        b.iter(|| black_box(Ciphertext::from_bytes(black_box(&bytes_r0)).unwrap()));
    });
    group.bench_function("ciphertext_from_bytes_r10", |b| {
        b.iter(|| black_box(Ciphertext::from_bytes(black_box(&bytes_r10)).unwrap()));
    });

    let kit_bytes = kit.to_bytes();
    group.bench_function("reader_kit_to_bytes", |b| {
        b.iter(|| black_box(kit.to_bytes()));
    });
    group.bench_function("reader_kit_from_bytes", |b| {
        b.iter(|| black_box(ReaderKit::from_bytes(black_box(&kit_bytes)).unwrap()));
    });
    group.finish();
}

fn bench_end_to_end(c: &mut Criterion) {
    // Full cycle: setup → mint 10 → encrypt → each decrypts. This is
    // a realistic "one batch of messages to 10 readers" workload.
    c.bench_function("e2e_setup_10mint_encrypt_10decrypt", |b| {
        b.iter(|| {
            let mut s = PublisherState::setup_with_seed(Config, SEED).unwrap();
            let kits: Vec<_> = (0..10).map(|_| s.mint().unwrap()).collect();
            let ct = s.encrypt(black_box(PAYLOAD)).unwrap();
            for kit in &kits {
                let pt = kit.decrypt(&ct).unwrap();
                black_box(pt);
            }
        });
    });
}

criterion_group!(
    benches,
    bench_setup,
    bench_mint,
    bench_encrypt,
    bench_decrypt,
    bench_wire_serialize,
    bench_end_to_end,
);
criterion_main!(benches);

// Suppress unused warning on TREE_HEIGHT import; it's here as a
// reminder that benchmarks are pinned to the h=7 v0.1 cap.
#[allow(dead_code)]
const _TREE_HEIGHT_CHECK: u8 = TREE_HEIGHT;
