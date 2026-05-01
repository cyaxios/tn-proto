//! Performance matrix for btn at h=8 (256-leaf tree).
//!
//! Walks message size × revocation count in two shapes:
//!
//! 1. **Raw cipher**: isolates the NNL subset-difference cover algorithm.
//!    As revocations grow, cover size grows too, so the ciphertext gets
//!    bigger even for the same plaintext — that's the evidence the test
//!    surfaces.
//!
//! 2. **Full Runtime emit**: the complete tn-core pipeline (classify +
//!    HMAC tokens + btn encrypt + row-hash + Ed25519 sign + envelope
//!    JSON + log append). Events/s as the user would see it.
//!
//! Run with:
//!
//! ```text
//! cargo test --release -p tn-core --test perf_matrix -- --ignored --nocapture
//! ```
//!
//! The `#[ignore]` attribute keeps these off the normal test path; opt-in
//! only. They take a few seconds each and print a markdown table.

#![cfg(feature = "fs")]

mod common;

use std::time::Instant;

/// Message sizes sweep (bytes). Small to large; 64 KB exceeds typical TN events
/// but surfaces the tail behavior.
const SIZES: &[usize] = &[64, 256, 1_024, 4_096, 16_384, 65_536];

/// Revocation counts at h=8. Max is 256 leaves; we leave a few unminted so
/// the encrypt never fails on a tree-exhausted error.
const REVOCATIONS: &[usize] = &[0, 1, 5, 25, 75, 150, 225];

/// Number of leaves we mint before running any measurement. Must be ≥ max
/// revocation value in REVOCATIONS.
const TOTAL_READERS: usize = 240;

/// Iterations per cell. Higher = tighter p50/p95; cost is test time.
const ITERS: usize = 200;

fn percentile(sorted_us: &[u64], p: f64) -> u64 {
    if sorted_us.is_empty() {
        return 0;
    }
    let idx = ((sorted_us.len() as f64) * p).min((sorted_us.len() - 1) as f64) as usize;
    sorted_us[idx]
}

fn mk_plaintext(n: usize) -> Vec<u8> {
    // Deterministic bytes — not all zeros so btn's AEAD can't short-circuit anything.
    (0..n).map(|i| (i & 0xff) as u8).collect()
}

#[test]
#[ignore = "perf matrix: opt-in via --ignored; takes 10-30s in release mode"]
fn btn_raw_cipher_matrix_h8() {
    eprintln!();
    eprintln!("### btn raw cipher — h=8, {TOTAL_READERS} readers minted, {ITERS} iters/cell");
    eprintln!();
    eprintln!(
        "| msg_size |  revoked | ct_len | enc_p50 µs | enc_p95 µs | events/s (p50) | overhead_pct |"
    );
    eprintln!(
        "|---------:|---------:|-------:|-----------:|-----------:|---------------:|-------------:|"
    );

    for &size in SIZES {
        let plaintext = mk_plaintext(size);
        for &n_rev in REVOCATIONS {
            assert!(
                n_rev < TOTAL_READERS,
                "n_rev {n_rev} must be < TOTAL_READERS {TOTAL_READERS}"
            );

            // Rebuild state fresh for each (size, n_rev) cell.
            let mut state = tn_btn::PublisherState::setup_with_seed(tn_btn::Config, [0x42u8; 32])
                .expect("setup");
            for _ in 0..TOTAL_READERS {
                state.mint().expect("mint");
            }
            for i in 0..n_rev {
                state
                    .revoke_by_leaf(tn_btn::LeafIndex(i as u64))
                    .expect("revoke_by_leaf");
            }

            // Warm-up — amortize any first-call costs.
            let _ = state.encrypt(&plaintext).expect("warmup encrypt");

            let mut durations_us = Vec::with_capacity(ITERS);
            let mut ct_len = 0usize;
            for _ in 0..ITERS {
                let t0 = Instant::now();
                let ct = state.encrypt(&plaintext).expect("encrypt");
                durations_us.push(t0.elapsed().as_micros() as u64);
                ct_len = ct.to_bytes().len();
            }
            durations_us.sort_unstable();
            let p50 = percentile(&durations_us, 0.50);
            let p95 = percentile(&durations_us, 0.95);
            let eps = 1_000_000u64.checked_div(p50).unwrap_or(0);
            // How much does the wire format bloat the plaintext?
            let overhead_pct = (ct_len as f64 / size as f64 - 1.0) * 100.0;

            eprintln!(
                "| {size:>8} | {n_rev:>8} | {ct_len:>6} | {p50:>10} | {p95:>10} | {eps:>14} | {overhead_pct:>11.1}% |"
            );
        }
    }
}

#[test]
#[ignore = "perf matrix: opt-in via --ignored; takes 25-70s in release mode"]
fn tn_core_full_ingest_matrix_h8() {
    // Full ingest = what a consumer does when it receives a log feed:
    //   1. Parse ndjson line
    //   2. Recompute row_hash from envelope fields and compare
    //   3. Verify Ed25519 signature on row_hash using the envelope's DID
    //   4. Verify chain linkage (prev_hash == previous row_hash)
    //   5. base64 decode ciphertext + btn decrypt + JSON parse plaintext
    //
    // This is the honest "events/s a subscriber can ingest" number.
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use std::collections::BTreeMap;
    use tn_core::chain::{compute_row_hash, GroupInput, RowHashInput, ZERO_HASH};
    use tn_core::signing::{signature_from_b64, DeviceKey};

    const BATCH: usize = 50;
    const REPEATS: usize = 10;

    eprintln!();
    eprintln!(
        "### tn-core full ingest (parse + verify sig + verify row_hash + verify chain + decrypt)"
    );
    eprintln!("### h=8, batch={BATCH}, {REPEATS} ingests/cell");
    eprintln!();
    eprintln!(
        "| msg_size | revoked | ingest_p50 µs/event | ingest_p95 µs/event | events/s (p50) |"
    );
    eprintln!(
        "|---------:|--------:|--------------------:|--------------------:|---------------:|"
    );

    for &size in SIZES {
        for &n_rev in REVOCATIONS {
            let td = tempfile::tempdir().expect("tempdir");
            let cer = common::setup_minimal_btn_ceremony_with_revocations(td.path(), n_rev);
            let rt = tn_core::Runtime::init(&cer.yaml_path).expect("init");

            let payload =
                String::from_utf8(mk_plaintext(size)).unwrap_or_else(|_| "x".repeat(size));
            for i in 0..BATCH {
                let mut f = serde_json::Map::new();
                f.insert("payload".into(), serde_json::Value::String(payload.clone()));
                rt.emit("info", "bench.ingestseed", f)
                    .unwrap_or_else(|e| panic!("seed {i}: {e}"));
            }

            // Load the raw ndjson once — we time pure ingest, not disk I/O.
            // Skip line 0 (tn.ceremony.init emitted on fresh creation); only time
            // the BATCH business events.
            let log_text = std::fs::read_to_string(rt.log_path()).expect("read log");
            let all_lines: Vec<&str> = log_text.lines().collect();
            // BATCH business events + 1 ceremony.init = BATCH + 1 total.
            assert_eq!(all_lines.len(), BATCH + 1);
            let lines: Vec<&str> = all_lines[1..].to_vec();

            // Build a handle to the single group's cipher for decrypt.
            // In a real subscriber this would be the cipher they built at init();
            // here we cheat by reusing rt.read_raw() to get the cipher indirectly.
            // Since Runtime doesn't expose cipher handles, we drive the whole
            // Runtime::read inside the timed region — matches the honest ingest cost.

            let mut per_event_us = Vec::with_capacity(REPEATS);
            for _ in 0..REPEATS {
                let t0 = Instant::now();

                // Ingest loop.
                let mut prev_hash = ZERO_HASH.to_string();
                for (idx, line) in lines.iter().enumerate() {
                    // 1. Parse.
                    let env: serde_json::Value = serde_json::from_str(line).expect("parse");

                    // 2. Extract fields needed for row_hash recomputation.
                    let did = env["did"].as_str().expect("did");
                    let timestamp = env["timestamp"].as_str().expect("ts");
                    let event_id = env["event_id"].as_str().expect("eid");
                    let event_type = env["event_type"].as_str().expect("et");
                    let level = env["level"].as_str().expect("lvl");
                    let env_prev = env["prev_hash"].as_str().expect("prev");
                    let env_row = env["row_hash"].as_str().expect("row");
                    let sig_b64 = env["signature"].as_str().expect("sig");

                    // 3. Reconstruct public_fields + groups for row_hash.
                    let mut public_fields: BTreeMap<String, serde_json::Value> = BTreeMap::new();
                    let mut groups: BTreeMap<String, GroupInput> = BTreeMap::new();
                    let reserved = [
                        "did",
                        "timestamp",
                        "event_id",
                        "event_type",
                        "level",
                        "sequence",
                        "prev_hash",
                        "row_hash",
                        "signature",
                    ];
                    for (k, v) in env.as_object().expect("obj") {
                        if reserved.contains(&k.as_str()) {
                            continue;
                        }
                        // Group payloads are objects with ciphertext + field_hashes.
                        if let Some(obj) = v.as_object() {
                            if obj.contains_key("ciphertext") && obj.contains_key("field_hashes") {
                                let ct_b64 = obj["ciphertext"].as_str().expect("ct");
                                let ct = STANDARD.decode(ct_b64).expect("ct b64");
                                let mut fh: BTreeMap<String, String> = BTreeMap::new();
                                for (fk, fv) in obj["field_hashes"].as_object().expect("fh") {
                                    fh.insert(fk.clone(), fv.as_str().expect("fh str").to_string());
                                }
                                groups.insert(
                                    k.clone(),
                                    GroupInput {
                                        ciphertext: ct,
                                        field_hashes: fh,
                                    },
                                );
                                continue;
                            }
                        }
                        public_fields.insert(k.clone(), v.clone());
                    }

                    // 4. Recompute row_hash and compare.
                    let recomputed = compute_row_hash(&RowHashInput {
                        did,
                        timestamp,
                        event_id,
                        event_type,
                        level,
                        prev_hash: env_prev,
                        public_fields: &public_fields,
                        groups: &groups,
                    });
                    assert_eq!(recomputed, env_row, "row_hash mismatch at event {idx}");

                    // 5. Verify Ed25519 signature on row_hash bytes.
                    let sig = signature_from_b64(sig_b64).expect("sig b64 decode");
                    assert!(
                        DeviceKey::verify_did(did, env_row.as_bytes(), &sig).expect("verify"),
                        "sig fail at event {idx}"
                    );

                    // 6. Verify chain linkage.
                    assert_eq!(env_prev, prev_hash, "chain break at event {idx}");
                    prev_hash = env_row.to_string();

                    // 7. Decrypt the group we can read — touches btn decrypt + JSON parse.
                    //    (We use rt.read here-equivalent: just iterate groups and decrypt
                    //    via the Runtime's cipher. Easiest: call a one-entry read helper.)
                    //    Hand-roll since Runtime doesn't expose a decrypt-one method yet.
                    //    Workaround: ask rt to read the whole file each iteration.
                    //    That's too slow — instead, precompute the decrypts once per
                    //    REPEATS pass isn't honest. So we DO include the decrypts by
                    //    doing a fresh rt.read_raw() after the loop and asserting count.
                }
                // Decrypt batch with the Runtime (this is what ingest actually costs):
                let entries = rt.read_raw().expect("read");
                // BATCH business events + 1 ceremony.init = BATCH + 1 total.
                assert_eq!(entries.len(), BATCH + 1);

                let total_us = t0.elapsed().as_micros() as u64;
                per_event_us.push(total_us / BATCH as u64);
            }
            drop(rt);
            per_event_us.sort_unstable();
            let p50 = percentile(&per_event_us, 0.50);
            let p95 = percentile(&per_event_us, 0.95);
            let eps = 1_000_000u64.checked_div(p50).unwrap_or(0);

            eprintln!("| {size:>8} | {n_rev:>7} | {p50:>19} | {p95:>19} | {eps:>14} |");
        }
    }
}

#[test]
#[ignore = "perf matrix: opt-in via --ignored; takes 20-60s in release mode"]
fn tn_core_runtime_read_matrix_h8() {
    // For each cell: emit BATCH events, then time how long it takes to read
    // them all back (decrypt all groups for this party). Per-event µs is the
    // total read time divided by BATCH.
    const BATCH: usize = 50;
    const REPEATS: usize = 10; // number of full read() invocations per cell

    eprintln!();
    eprintln!(
        "### tn-core Runtime::read — full pipeline, h=8, batch={BATCH}, {REPEATS} reads/cell"
    );
    eprintln!();
    eprintln!("| msg_size | revoked | read_p50 µs/event | read_p95 µs/event | events/s (p50) |");
    eprintln!("|---------:|--------:|------------------:|------------------:|---------------:|");

    for &size in SIZES {
        for &n_rev in REVOCATIONS {
            let td = tempfile::tempdir().expect("tempdir");
            let cer = common::setup_minimal_btn_ceremony_with_revocations(td.path(), n_rev);
            let rt = tn_core::Runtime::init(&cer.yaml_path).expect("init");

            let payload =
                String::from_utf8(mk_plaintext(size)).unwrap_or_else(|_| "x".repeat(size));

            // Seed BATCH events into the log.
            for i in 0..BATCH {
                let mut f = serde_json::Map::new();
                f.insert("payload".into(), serde_json::Value::String(payload.clone()));
                rt.emit("info", "bench.readseed", f)
                    .unwrap_or_else(|e| panic!("seed emit {i} failed: {e}"));
            }

            // Warm-up read.
            let _ = rt.read_raw().expect("warmup read");

            let mut per_event_us = Vec::with_capacity(REPEATS);
            for _ in 0..REPEATS {
                let t0 = Instant::now();
                let entries = rt.read_raw().expect("read");
                let total_us = t0.elapsed().as_micros() as u64;
                // BATCH business events + 1 ceremony.init = BATCH + 1 total.
                assert_eq!(
                    entries.len(),
                    BATCH + 1,
                    "expected {BATCH} business + 1 ceremony.init"
                );
                per_event_us.push(total_us / BATCH as u64);
            }
            drop(rt);
            per_event_us.sort_unstable();
            let p50 = percentile(&per_event_us, 0.50);
            let p95 = percentile(&per_event_us, 0.95);
            let eps = 1_000_000u64.checked_div(p50).unwrap_or(0);

            eprintln!("| {size:>8} | {n_rev:>7} | {p50:>17} | {p95:>17} | {eps:>14} |");
        }
    }
}

#[test]
#[ignore = "perf matrix: opt-in via --ignored; takes 15-45s in release mode"]
fn tn_core_runtime_emit_matrix_h8() {
    eprintln!();
    eprintln!("### tn-core Runtime::emit — full pipeline, h=8, {ITERS} iters/cell");
    eprintln!();
    eprintln!("| msg_size | revoked | emit_p50 µs | emit_p95 µs | events/s (p50) |");
    eprintln!("|---------:|--------:|------------:|------------:|---------------:|");

    for &size in SIZES {
        for &n_rev in REVOCATIONS {
            // Each cell rebuilds a fresh ceremony so revocations are isolated.
            let td = tempfile::tempdir().expect("tempdir");
            let cer = common::setup_minimal_btn_ceremony_with_revocations(td.path(), n_rev);
            let rt = tn_core::Runtime::init(&cer.yaml_path).expect("init");

            let payload = String::from_utf8(mk_plaintext(size)).unwrap_or_else(|_| {
                // Non-UTF8 bytes would fail canonical JSON; fall back to "x" repeat.
                "x".repeat(size)
            });

            // Warm-up.
            let mut warm = serde_json::Map::new();
            warm.insert("payload".into(), serde_json::Value::String(payload.clone()));
            rt.emit("info", "bench.warmup", warm).expect("warmup emit");

            let mut durations_us = Vec::with_capacity(ITERS);
            for i in 0..ITERS {
                let mut f = serde_json::Map::new();
                f.insert("payload".into(), serde_json::Value::String(payload.clone()));
                let t0 = Instant::now();
                rt.emit("info", "bench.matrix", f)
                    .unwrap_or_else(|e| panic!("emit {i} failed: {e}"));
                durations_us.push(t0.elapsed().as_micros() as u64);
            }
            drop(rt);
            durations_us.sort_unstable();
            let p50 = percentile(&durations_us, 0.50);
            let p95 = percentile(&durations_us, 0.95);
            let eps = 1_000_000u64.checked_div(p50).unwrap_or(0);

            eprintln!("| {size:>8} | {n_rev:>7} | {p50:>11} | {p95:>11} | {eps:>14} |");
        }
    }
}
