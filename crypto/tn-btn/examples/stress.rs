//! Long-running stress test: runs realistic encrypt/decrypt cycles in
//! a tight loop, reporting throughput and catching correctness
//! regressions.
//!
//! ## Usage
//!
//! ```text
//! cargo run --release --example stress -- [--duration-secs N] [--iters M]
//! ```
//!
//! Defaults: run until Ctrl+C. Reports every 5 seconds.
//!
//! ## What each iteration does
//!
//! 1. Set up a fresh PublisherState.
//! 2. Mint 20 readers.
//! 3. Randomly revoke 0-10 of them.
//! 4. Encrypt a 256-byte payload.
//! 5. Every non-revoked reader decrypts and verifies plaintext.
//! 6. Every revoked reader confirms NotEntitled.
//! 7. Serialize the ciphertext to bytes, deserialize, decrypt again —
//!    verify wire format round-trip.
//! 8. Count successful iterations; abort on any failure.
//!
//! Each iteration exercises every subsystem: cover computation, cache,
//! AEAD, AES-KW, wire format. Failures here mean a real bug; pass
//! means the library is stable under load.

use std::env;
use std::time::{Duration, Instant};
use tn_btn::{config::TREE_HEIGHT, Ciphertext, Config, Error, PublisherState, ReaderKit};

fn parse_arg<T: std::str::FromStr>(name: &str, default: T) -> T {
    for arg in env::args() {
        if let Some(value) = arg.strip_prefix(&format!("--{name}=")) {
            if let Ok(parsed) = value.parse::<T>() {
                return parsed;
            }
        }
    }
    default
}

struct Stats {
    iters: u64,
    total_encrypts: u64,
    total_decrypts: u64,
    total_bytes_sealed: u64,
    total_bytes_wire: u64,
    failures: u64,
    start: Instant,
    last_report: Instant,
}

impl Stats {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            iters: 0,
            total_encrypts: 0,
            total_decrypts: 0,
            total_bytes_sealed: 0,
            total_bytes_wire: 0,
            failures: 0,
            start: now,
            last_report: now,
        }
    }

    fn maybe_report(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_report) < Duration::from_secs(5) {
            return;
        }
        let elapsed = now.duration_since(self.start);
        let secs = elapsed.as_secs_f64();
        let iter_rate = self.iters as f64 / secs;
        let enc_rate = self.total_encrypts as f64 / secs;
        let dec_rate = self.total_decrypts as f64 / secs;
        let enc_throughput_mb = (self.total_bytes_sealed as f64 / secs) / (1024.0 * 1024.0);
        println!(
            "[{:>7.0}s] iter={:>10} ({:>7.0}/s)  encrypts={:>10} ({:>7.0}/s, {:>6.2} MB/s) \
             decrypts={:>10} ({:>7.0}/s)  wire_bytes={:>12}  failures={}",
            secs,
            self.iters,
            iter_rate,
            self.total_encrypts,
            enc_rate,
            enc_throughput_mb,
            self.total_decrypts,
            dec_rate,
            self.total_bytes_wire,
            self.failures,
        );
        self.last_report = now;
    }

    fn final_report(&self) {
        let elapsed = self.start.elapsed();
        let secs = elapsed.as_secs_f64();
        println!();
        println!("=== Final report ===");
        println!("  Duration:       {:.1}s", secs);
        println!(
            "  Iterations:     {} ({:.0}/s avg)",
            self.iters,
            self.iters as f64 / secs
        );
        println!(
            "  Encrypts:       {} ({:.0}/s)",
            self.total_encrypts,
            self.total_encrypts as f64 / secs
        );
        println!(
            "  Decrypts:       {} ({:.0}/s)",
            self.total_decrypts,
            self.total_decrypts as f64 / secs
        );
        println!(
            "  Sealed bytes:   {:.2} MB ({:.2} MB/s)",
            self.total_bytes_sealed as f64 / (1024.0 * 1024.0),
            (self.total_bytes_sealed as f64 / secs) / (1024.0 * 1024.0),
        );
        println!(
            "  Wire bytes:     {:.2} MB",
            self.total_bytes_wire as f64 / (1024.0 * 1024.0)
        );
        println!("  Failures:       {}", self.failures);
        if self.failures == 0 {
            println!("  STATUS:         OK");
        } else {
            println!("  STATUS:         FAILURES DETECTED — investigate");
        }
    }
}

/// Pseudo-random generator for reproducible stress runs. Uses a simple
/// LCG seeded from the iteration count so the whole run is
/// deterministic — easy to reproduce a specific failure.
fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

fn run_one_iteration(rng: &mut u64, seed_byte: u8) -> Result<IterOutcome, String> {
    let seed = [seed_byte; 32];
    let mut state =
        PublisherState::setup_with_seed(Config, seed).map_err(|e| format!("setup: {e}"))?;

    // Mint 20 readers.
    let mut kits: Vec<_> = (0..20)
        .map(|_| state.mint().map_err(|e| format!("mint: {e}")))
        .collect::<Result<_, _>>()?;

    // Randomly revoke 0-10 readers.
    let revoke_count = (lcg(rng) % 11) as usize;
    let mut revoked_leaves = std::collections::BTreeSet::new();
    for _ in 0..revoke_count {
        let idx = (lcg(rng) as usize) % kits.len();
        if revoked_leaves.insert(kits[idx].leaf()) {
            state
                .revoke(&kits[idx])
                .map_err(|e| format!("revoke: {e}"))?;
        }
    }

    // Encrypt a 256-byte payload with some variation per-iter.
    let mut payload = [0u8; 256];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(seed_byte);
    }
    let ct = state
        .encrypt(&payload)
        .map_err(|e| format!("encrypt: {e}"))?;

    // Each reader: survivors decrypt and get matching plaintext;
    // revoked return NotEntitled.
    let mut decrypt_count = 0u64;
    for kit in &mut kits {
        let is_revoked = revoked_leaves.contains(&kit.leaf());
        match kit.decrypt(&ct) {
            Ok(pt) if !is_revoked => {
                if pt != payload {
                    return Err(format!(
                        "plaintext mismatch for survivor leaf {:?}: got {} bytes, expected {}",
                        kit.leaf(),
                        pt.len(),
                        payload.len(),
                    ));
                }
                decrypt_count += 1;
            }
            Ok(_) if is_revoked => {
                return Err(format!(
                    "revoked leaf {:?} decrypted successfully (should have been NotEntitled)",
                    kit.leaf(),
                ));
            }
            Err(Error::NotEntitled) if is_revoked => {
                // Expected.
            }
            Err(e) if !is_revoked => {
                return Err(format!(
                    "survivor leaf {:?} failed to decrypt: {e}",
                    kit.leaf(),
                ));
            }
            _ => {}
        }
    }

    // Wire round-trip: serialize ct, deserialize, decrypt with one survivor.
    let wire = ct.to_bytes();
    let round_tripped = Ciphertext::from_bytes(&wire).map_err(|e| format!("ct from_bytes: {e}"))?;
    let survivor = kits
        .iter()
        .find(|k| !revoked_leaves.contains(&k.leaf()))
        .cloned();
    if let Some(survivor) = survivor {
        let pt2 = survivor
            .decrypt(&round_tripped)
            .map_err(|e| format!("wire round-trip decrypt: {e}"))?;
        if pt2 != payload {
            return Err("wire round-trip plaintext mismatch".to_string());
        }
        decrypt_count += 1;

        // Wire round-trip the kit too.
        let kit_wire = survivor.to_bytes();
        let kit2 = ReaderKit::from_bytes(&kit_wire).map_err(|e| format!("kit from_bytes: {e}"))?;
        let pt3 = kit2
            .decrypt(&round_tripped)
            .map_err(|e| format!("kit wire round-trip decrypt: {e}"))?;
        if pt3 != payload {
            return Err("kit wire round-trip plaintext mismatch".to_string());
        }
        decrypt_count += 1;
    }

    Ok(IterOutcome {
        decrypts: decrypt_count,
        bytes_sealed: payload.len() as u64,
        wire_bytes: wire.len() as u64,
    })
}

struct IterOutcome {
    decrypts: u64,
    bytes_sealed: u64,
    wire_bytes: u64,
}

fn main() {
    let duration_secs: u64 = parse_arg("duration-secs", u64::MAX);
    let max_iters: u64 = parse_arg("iters", u64::MAX);

    println!("btn stress test");
    println!("  TREE_HEIGHT:    {TREE_HEIGHT}");
    println!(
        "  duration_secs:  {}",
        if duration_secs == u64::MAX {
            "unlimited".into()
        } else {
            duration_secs.to_string()
        }
    );
    println!(
        "  max_iters:      {}",
        if max_iters == u64::MAX {
            "unlimited".into()
        } else {
            max_iters.to_string()
        }
    );
    println!("  payload_bytes:  256");
    println!();
    println!("{:-<120}", "");

    let mut stats = Stats::new();
    let mut rng = 0xDEADBEEFu64;
    let deadline = Duration::from_secs(duration_secs);

    loop {
        if stats.start.elapsed() >= deadline {
            break;
        }
        if stats.iters >= max_iters {
            break;
        }

        // Cycle the seed byte so different iterations use different
        // publisher keys (exercises more of the key-derivation space).
        let seed_byte = (stats.iters % 256) as u8;
        match run_one_iteration(&mut rng, seed_byte) {
            Ok(outcome) => {
                stats.iters += 1;
                stats.total_encrypts += 1;
                stats.total_decrypts += outcome.decrypts;
                stats.total_bytes_sealed += outcome.bytes_sealed;
                stats.total_bytes_wire += outcome.wire_bytes;
            }
            Err(e) => {
                stats.failures += 1;
                eprintln!(
                    "!!! FAILURE on iter {} (rng={:#x}, seed_byte={}): {e}",
                    stats.iters, rng, seed_byte,
                );
                // Abort on first failure — quicker signal than
                // accumulating over a long run.
                break;
            }
        }

        stats.maybe_report();
    }

    stats.final_report();
    if stats.failures > 0 {
        std::process::exit(1);
    }
}
