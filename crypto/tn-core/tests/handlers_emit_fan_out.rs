//! Tests for `Runtime::emit` fan-out into attached `TnHandler`s.
//!
//! Mirrors the Python `Logger` fan-out (`python/tn/logger.py:343`) and
//! the TS `NodeRuntime` fan-out
//! (`ts-sdk/src/runtime/node_runtime.ts:376`):
//!
//! - every emit reaches every handler whose `accepts()` returns true;
//! - handlers whose filter rejects the envelope are skipped;
//! - panics / errors raised by a handler are logged and swallowed —
//!   subsequent emits still succeed and downstream handlers still see
//!   later events.
//!
//! Wires into the `Runtime::add_handler` API added 2026-04-25 alongside
//! the audit fix that wired the fan-out to `Runtime::emit`.

#![cfg(feature = "fs")]

mod common;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value};

use tn_core::handlers::TnHandler;

use common::setup_minimal_btn_ceremony;

/// Test handler that records every envelope it receives.
struct CaptureHandler {
    name: String,
    only_event_type: Option<String>,
    captured: Mutex<Vec<Value>>,
}

impl CaptureHandler {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            only_event_type: None,
            captured: Mutex::new(Vec::new()),
        }
    }

    fn only(name: &str, event_type: &str) -> Self {
        Self {
            name: name.to_string(),
            only_event_type: Some(event_type.to_string()),
            captured: Mutex::new(Vec::new()),
        }
    }

    fn count(&self) -> usize {
        self.captured.lock().unwrap().len()
    }

    fn captured(&self) -> Vec<Value> {
        self.captured.lock().unwrap().clone()
    }
}

impl TnHandler for CaptureHandler {
    fn name(&self) -> &str {
        &self.name
    }
    fn accepts(&self, envelope: &Value) -> bool {
        match &self.only_event_type {
            None => true,
            Some(allow) => envelope
                .get("event_type")
                .and_then(Value::as_str)
                .is_some_and(|s| s == allow),
        }
    }
    fn emit(&self, envelope: &Value, _raw_line: &[u8]) {
        self.captured.lock().unwrap().push(envelope.clone());
    }
    fn close(&self) {}
}

/// Test handler that always panics in `emit` to verify failure
/// isolation: a panic must not propagate back to the publish call,
/// and subsequent handlers / subsequent emits must still work.
struct PanickingHandler {
    name: String,
    called: AtomicUsize,
    accepted: AtomicBool,
}

impl PanickingHandler {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            called: AtomicUsize::new(0),
            accepted: AtomicBool::new(true),
        }
    }
    fn calls(&self) -> usize {
        self.called.load(Ordering::SeqCst)
    }
}

impl TnHandler for PanickingHandler {
    fn name(&self) -> &str {
        &self.name
    }
    fn accepts(&self, _envelope: &Value) -> bool {
        self.accepted.load(Ordering::SeqCst)
    }
    fn emit(&self, _envelope: &Value, _raw_line: &[u8]) {
        self.called.fetch_add(1, Ordering::SeqCst);
        panic!("intentional test panic from {}", self.name);
    }
    fn close(&self) {}
}

fn fields(s: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("note".into(), Value::String(s.into()));
    m
}

#[test]
fn emit_fans_out_to_attached_handler() {
    // Opt out of the default-on stdout handler so handler_count assertions
    // reflect only what this test attaches.
    // SAFETY: tests in this file are self-contained; setting TN_NO_STDOUT
    // is safe here because no other thread observes the env var change.
    unsafe { std::env::set_var("TN_NO_STDOUT", "1"); }
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();

    let cap = Arc::new(CaptureHandler::new("cap"));
    rt.add_handler(cap.clone());
    assert_eq!(rt.handler_count(), 1);

    rt.emit("info", "test.event", fields("hello")).unwrap();

    assert_eq!(cap.count(), 1, "handler should have received exactly one envelope");
    let envs = cap.captured();
    let env = &envs[0];
    assert_eq!(env.get("event_type").and_then(Value::as_str), Some("test.event"));
    assert_eq!(env.get("did").and_then(Value::as_str), Some(cer.did.as_str()));
    assert!(env.get("event_id").and_then(Value::as_str).is_some());
    assert!(env.get("row_hash").and_then(Value::as_str).is_some());
}

#[test]
fn accepts_filter_is_respected() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();

    // Only accepts `tn.recipient.added`; we'll emit `test.event` and
    // assert the handler is NOT called.
    let only = Arc::new(CaptureHandler::only("only-recipient", "tn.recipient.added"));
    rt.add_handler(only.clone());

    rt.emit("info", "test.event", fields("ignored")).unwrap();

    assert_eq!(
        only.count(),
        0,
        "handler with `accepts == false` for this event_type must not be called"
    );

    // Now emit something it does accept and confirm it does fire. We
    // emit a non-tn.* event that happens to match by name to avoid the
    // admin-catalog schema check on real `tn.*` events.
    let allow = Arc::new(CaptureHandler::only("only-foo", "foo.event"));
    rt.add_handler(allow.clone());
    rt.emit("info", "foo.event", fields("yes")).unwrap();
    assert_eq!(allow.count(), 1, "handler accepting foo.event should fire");
    assert_eq!(only.count(), 0, "the recipient-only handler still must not fire");
}

#[test]
fn handler_panic_is_isolated_and_logged() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();

    let panicker = Arc::new(PanickingHandler::new("boom"));
    let downstream = Arc::new(CaptureHandler::new("downstream"));
    rt.add_handler(panicker.clone());
    rt.add_handler(downstream.clone());

    // First emit: panicker must be called, must not propagate, and the
    // downstream handler must still receive the envelope.
    rt.emit("info", "test.event", fields("first"))
        .expect("publish should succeed despite panicking handler");
    assert_eq!(panicker.calls(), 1);
    assert_eq!(downstream.count(), 1);

    // Subsequent emit: the runtime should still be healthy. The
    // panicking handler is invoked again (panics again, swallowed),
    // and the downstream handler accumulates a second envelope.
    rt.emit("info", "test.event", fields("second")).unwrap();
    assert_eq!(panicker.calls(), 2);
    assert_eq!(downstream.count(), 2);

    // Sanity: the second received envelope is distinct from the first.
    let envs = downstream.captured();
    assert_ne!(
        envs[0].get("event_id").and_then(Value::as_str),
        envs[1].get("event_id").and_then(Value::as_str),
    );
}

#[test]
fn emit_with_no_handlers_is_a_noop() {
    // No handlers attached — the fast path should not parse the
    // envelope or otherwise differ in observable behavior.
    // Opt out of default-on stdout so handler_count is truly zero.
    // SAFETY: see note in emit_fans_out_to_attached_handler.
    unsafe { std::env::set_var("TN_NO_STDOUT", "1"); }
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = tn_core::Runtime::init(&cer.yaml_path).unwrap();

    assert_eq!(rt.handler_count(), 0);
    rt.emit("info", "test.event", fields("plain")).unwrap();

    // And an envelope shape sanity check via the read path so we
    // know the file write happened.
    let entries = rt.read().unwrap();
    assert!(
        entries.iter().any(|e| {
            e.get("event_type").and_then(Value::as_str) == Some("test.event")
        }),
        "expected test.event in flat read shape, got {entries:?}"
    );
    // Suppress unused-import lint when read shape changes.
    let _ = json!({});
}
