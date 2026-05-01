#![cfg(feature = "fs")]
//! End-to-end CLI test: init, log, read via a subprocess.

mod common;

use common::setup_minimal_btn_ceremony;
use std::process::Command;

#[test]
fn cli_init_log_read_roundtrip() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());

    // The bin path is provided by cargo via CARGO_BIN_EXE_<name>.
    let bin = env!("CARGO_BIN_EXE_tn-core-cli");

    // init
    let out = Command::new(bin)
        .args(["--yaml", cer.yaml_path.to_str().unwrap(), "init"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "init failed: stderr=\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("did=did:key:z"), "init stdout: {stdout}");

    // log
    let out = Command::new(bin)
        .args([
            "--yaml",
            cer.yaml_path.to_str().unwrap(),
            "log",
            "--event-type",
            "order.created",
            "amount=100",
            "note=hello",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "log failed: stderr=\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let log_out = String::from_utf8_lossy(&out.stdout);
    assert!(log_out.contains("\"sequence\":1"), "log stdout: {log_out}");

    // read
    let out = Command::new(bin)
        .args(["--yaml", cer.yaml_path.to_str().unwrap(), "read"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "read failed: stderr=\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let read_out = String::from_utf8_lossy(&out.stdout);
    assert!(
        read_out.contains("order.created"),
        "read stdout: {read_out}"
    );
    assert!(
        read_out.contains("\"amount\":100"),
        "read should show decrypted payload: {read_out}"
    );
}
