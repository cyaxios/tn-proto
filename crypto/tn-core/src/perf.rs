//! Stage-level perf instrumentation for the emit hot path.
//!
//! Enabled when the `TN_PERF_TRACE` env var is set at process start.
//! Each named stage accumulates `count` and `total_ns` into a static
//! `Mutex<HashMap>` keyed by `&'static str`. Snapshot via
//! [`snapshot`]; reset via [`reset`].
//!
//! Why a Mutex over atomics: the hash map allocation is amortized
//! across the whole process; per-stage updates are
//! `lock + insert/update + unlock`, which on Windows is ~80 ns
//! uncontended (Linux `parking_lot`-style would be similar). Cheap
//! relative to the kilonanosecond stages we're measuring. Atomics
//! would be faster but would force us to pre-declare every stage at
//! compile time, which makes adding new stages annoying.
//!
//! When disabled the only cost is a single `AtomicBool::load(Relaxed)`
//! at each [`time_stage`] entry — branch-predicted out for the
//! disabled path.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

static ENABLED: AtomicBool = AtomicBool::new(false);

fn counters() -> &'static Mutex<HashMap<&'static str, StageStats>> {
    static CELL: OnceLock<Mutex<HashMap<&'static str, StageStats>>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Per-stage accumulator.
#[derive(Default, Clone, Copy)]
pub struct StageStats {
    /// Number of times the stage executed.
    pub count: u64,
    /// Sum of stage wall-clock durations in nanoseconds.
    pub total_ns: u64,
}

/// Initialize from the env. Call once at process start (e.g. from
/// `Runtime::init`). Idempotent.
pub fn init_from_env() {
    let on = std::env::var("TN_PERF_TRACE")
        .ok()
        .filter(|s| !s.is_empty() && s != "0")
        .is_some();
    ENABLED.store(on, Ordering::Relaxed);
}

/// `true` if instrumentation was turned on via env. Branchless-friendly.
#[inline]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Time `f`, attributing the elapsed nanoseconds to `stage`.
///
/// When instrumentation is disabled this is just `f()` plus one
/// atomic-bool load (predicted false). When enabled, two `Instant`
/// reads and one mutex acquisition per call.
#[inline]
pub fn time_stage<F, R>(stage: &'static str, f: F) -> R
where
    F: FnOnce() -> R,
{
    if !enabled() {
        return f();
    }
    let t0 = Instant::now();
    let r = f();
    let dt_ns = t0.elapsed().as_nanos() as u64;
    record(stage, dt_ns);
    r
}

/// Attribute `ns` nanoseconds to `stage` directly. Useful when the
/// caller already captured an `Instant` (e.g. inside a closure that
/// can `return` early) and wants to record without re-wrapping.
///
/// When [`enabled`] is false this still acquires the mutex — use
/// [`enabled`] to guard the timing capture itself in tight code paths.
#[inline]
pub fn record_ns(stage: &'static str, ns: u64) {
    record(stage, ns);
}

fn record(stage: &'static str, ns: u64) {
    let Ok(mut g) = counters().lock() else {
        return;
    };
    let s = g.entry(stage).or_default();
    s.count += 1;
    s.total_ns = s.total_ns.saturating_add(ns);
}

/// Snapshot the current accumulator state.
///
/// Returned vector is sorted by `total_ns` descending so the most
/// expensive stages appear first.
pub fn snapshot() -> Vec<(&'static str, StageStats)> {
    let g = counters().lock().expect("perf counters mutex poisoned");
    let mut out: Vec<(&'static str, StageStats)> = g.iter().map(|(k, v)| (*k, *v)).collect();
    out.sort_by(|a, b| b.1.total_ns.cmp(&a.1.total_ns));
    out
}

/// Zero all accumulators. Useful when the caller wants to discard
/// warmup costs before a measurement window.
pub fn reset() {
    let mut g = counters().lock().expect("perf counters mutex poisoned");
    g.clear();
}
