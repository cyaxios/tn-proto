//! Integration tests for `Runtime::seal` / `Runtime::unseal` — the
//! portable sealed-object verbs. Mirrors the Python oracle suite in
//! `python/tests/test_seal_unseal.py` case-for-case where the behavior
//! is shared, plus the Rust-specific key-bag seams.

#![cfg(feature = "fs")]

mod common;

use std::collections::BTreeMap;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Map, Value};

use common::setup_minimal_btn_ceremony;
use tn_core::chain::{compute_row_hash, GroupInput, RowHashInput, ZERO_HASH};
use tn_core::runtime::unseal_as_recipient;
use tn_core::signing::signature_from_b64;
use tn_core::{DeviceKey, Error, Runtime, SealOptions, UnsealOptions};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn fields(pairs: &[(&str, Value)]) -> Map<String, Value> {
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert((*k).to_string(), v.clone());
    }
    m
}

fn no_receipt() -> SealOptions {
    SealOptions {
        receipt: false,
        ..SealOptions::default()
    }
}

/// Ceremony variant whose `tn.*` events route to the default dedicated
/// admin file (`./.tn/admin/admin.ndjson`) instead of the main log, so
/// the receipt tests read the surface Python's `tn.read(log="admin")`
/// reads.
fn setup_ceremony_with_admin_pel(root: &Path) -> common::BtnCeremony {
    let cer = setup_minimal_btn_ceremony(root);
    let yaml = std::fs::read_to_string(&cer.yaml_path).unwrap();
    let patched = yaml.replace(
        "protocol_events_location: main_log",
        "protocol_events_location: \"./.tn/admin/admin.ndjson\"",
    );
    assert_ne!(
        yaml, patched,
        "ceremony yaml must carry the PEL key to patch"
    );
    std::fs::write(&cer.yaml_path, patched).unwrap();
    cer
}

/// Ceremony variant that routes `pv` to public_fields (mirror of
/// Python's `_ceremony_with_public`). Public values feed the row hash
/// as `str(value)`; group fields do not — the fragile guard only fires
/// in public position.
fn setup_ceremony_with_public_pv(root: &Path) -> common::BtnCeremony {
    let cer = setup_minimal_btn_ceremony(root);
    let yaml = std::fs::read_to_string(&cer.yaml_path).unwrap();
    let patched = yaml.replace("public_fields: []", "public_fields: [pv]");
    assert_ne!(
        yaml, patched,
        "ceremony yaml must carry public_fields to patch"
    );
    std::fs::write(&cer.yaml_path, patched).unwrap();
    cer
}

fn read_ndjson(path: &Path) -> Vec<Value> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

// ---------------------------------------------------------------------------
// R3 — Runtime::seal
// ---------------------------------------------------------------------------

#[test]
fn seal_returns_standalone_envelope() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let sealed = rt
        .seal(
            "obj.invoice.v1",
            fields(&[("amount", json!(9800)), ("customer", json!("acme"))]),
            &no_receipt(),
        )
        .unwrap();
    let env = &sealed.envelope;

    // Standalone conventions.
    assert_eq!(env["sequence"], json!(0));
    assert_eq!(env["prev_hash"], json!(""));
    assert_eq!(env["level"], json!(""));
    assert_eq!(env["tn_sealed"], json!(1));
    assert_eq!(env["event_type"], json!("obj.invoice.v1"));

    // Fields are encrypted, not in the clear.
    assert!(!env.contains_key("amount"));
    assert!(!env.contains_key("customer"));
    assert!(env["default"]["ciphertext"].is_string());

    // Always signed, and the signature verifies.
    let row_hash = env["row_hash"].as_str().unwrap();
    let sig = signature_from_b64(env["signature"].as_str().unwrap()).unwrap();
    assert!(DeviceKey::verify_did(
        env["device_identity"].as_str().unwrap(),
        row_hash.as_bytes(),
        &sig
    )
    .unwrap());

    // row_hash is honestly derived from the envelope contents, with
    // public_fields = {tn_sealed: 1} ONLY (no run_id injection, no
    // agent-policy splice — seal bypasses the emit prelude).
    let ct = STANDARD
        .decode(env["default"]["ciphertext"].as_str().unwrap())
        .unwrap();
    let field_hashes: BTreeMap<String, String> = env["default"]["field_hashes"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
        .collect();
    let mut groups = BTreeMap::new();
    groups.insert(
        "default".to_string(),
        GroupInput {
            ciphertext: ct,
            field_hashes,
        },
    );
    let mut public = BTreeMap::new();
    public.insert("tn_sealed".to_string(), json!(1));
    let expected = compute_row_hash(&RowHashInput {
        device_identity: env["device_identity"].as_str().unwrap(),
        timestamp: env["timestamp"].as_str().unwrap(),
        event_id: env["event_id"].as_str().unwrap(),
        event_type: "obj.invoice.v1",
        level: "",
        prev_hash: "",
        public_fields: &public,
        groups: &groups,
    });
    assert_eq!(expected, row_hash);

    // No aad passed -> no tn_aad echo.
    assert!(!env.contains_key("tn_aad"));
}

#[test]
fn seal_rejects_reserved_field() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let err = rt
        .seal(
            "obj.test.v1",
            fields(&[("tn_sealed", json!(1))]),
            &no_receipt(),
        )
        .unwrap_err();
    match err {
        Error::InvalidConfig(msg) => assert!(msg.contains("tn_sealed"), "{msg}"),
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
}

#[test]
fn seal_does_not_disturb_chain() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    rt.seal("obj.test.v1", fields(&[("x", json!(1))]), &no_receipt())
        .unwrap();
    // Chains are per-event_type: log the SAME type the seal used. If
    // seal had advanced that chain, this row would be sequence 2 with a
    // real prev_hash instead of the genesis link.
    rt.log("obj.test.v1", fields(&[("y", json!(2))])).unwrap();

    let rows = read_ndjson(rt.log_path());
    let row = rows
        .iter()
        .find(|e| e["event_type"] == json!("obj.test.v1"))
        .expect("logged row present");
    assert_eq!(row["sequence"], json!(1));
    assert_eq!(row["prev_hash"], json!(ZERO_HASH));
}

#[test]
fn seal_receipt_row_written_by_default() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_ceremony_with_admin_pel(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let sealed = rt
        .seal(
            "obj.invoice.v1",
            fields(&[("amount", json!(1))]),
            &SealOptions::default(),
        )
        .unwrap();

    let admin_log = td.path().join(".tn").join("admin").join("admin.ndjson");
    let receipts: Vec<Value> = read_ndjson(&admin_log)
        .into_iter()
        .filter(|e| e["event_type"] == json!("tn.object.sealed"))
        .collect();
    assert_eq!(receipts.len(), 1, "exactly one receipt row");
    // The receipt's payload rides in the encrypted default group; read
    // it back through the runtime's own read path (decrypts with the
    // ceremony's kit).
    let raw = rt.read_from(&admin_log).unwrap();
    let receipt = raw
        .iter()
        .find(|e| e.envelope.get("event_type").and_then(Value::as_str) == Some("tn.object.sealed"))
        .expect("receipt readable through read_from(admin log)");
    let body = &receipt.plaintext_per_group["default"];
    assert_eq!(body["object_id"], sealed.envelope["row_hash"]);
    assert_eq!(body["object_type"], json!("obj.invoice.v1"));
    assert_eq!(body["groups"], json!(["default"]));
}

#[test]
fn seal_receipt_false_writes_nothing() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_ceremony_with_admin_pel(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    rt.seal(
        "obj.invoice.v1",
        fields(&[("amount", json!(1))]),
        &no_receipt(),
    )
    .unwrap();

    let admin_log = td.path().join(".tn").join("admin").join("admin.ndjson");
    let receipts: Vec<Value> = read_ndjson(&admin_log)
        .into_iter()
        .filter(|e| e["event_type"] == json!("tn.object.sealed"))
        .collect();
    assert!(
        receipts.is_empty(),
        "receipt=false must write no receipt row"
    );
}

#[test]
fn seal_rejects_fragile_public_value() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_ceremony_with_public_pv(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    // A public value a foreign JSON runtime would silently reformat
    // must be refused at seal time, not fail at a remote unseal.
    for fragile in [
        json!(1.0),                      // integral float
        json!(3.14),                     // non-integral float
        json!(9_007_199_254_740_993u64), // 2^53 + 1
        json!([1.0, 2]),                 // float in list
        json!({"amt": 5.0}),             // float in dict
    ] {
        let err = rt
            .seal(
                "obj.rt.v1",
                fields(&[("pv", fragile.clone())]),
                &no_receipt(),
            )
            .unwrap_err();
        match err {
            Error::InvalidConfig(msg) => {
                assert!(msg.contains("public field"), "pv={fragile}: {msg}");
            }
            other => panic!("pv={fragile}: expected InvalidConfig, got {other:?}"),
        }
    }

    // The same fragile value in an ENCRYPTED group (the default) seals
    // fine — group fields are hashed as opaque ciphertext.
    rt.seal(
        "obj.rt.v1",
        fields(&[("price", json!(19.0))]),
        &no_receipt(),
    )
    .unwrap();
}

#[test]
fn seal_wire_string_has_no_trailing_newline_and_reparses_identically() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let sealed = rt
        .seal("obj.test.v1", fields(&[("x", json!(1))]), &no_receipt())
        .unwrap();
    assert!(
        !sealed.wire.ends_with('\n'),
        "wire must have no trailing newline"
    );
    assert!(!sealed.wire.contains('\n'), "wire is a single line");
    let reparsed: Map<String, Value> = serde_json::from_str(&sealed.wire).unwrap();
    assert_eq!(reparsed, sealed.envelope);
}

// ---------------------------------------------------------------------------
// R4 — Runtime::unseal + key-bag walk
// ---------------------------------------------------------------------------

fn assert_verify_err(err: Error) -> (Vec<String>, u64, String) {
    match err {
        Error::SealedObjectVerify {
            failed_checks,
            sequence,
            event_type,
        } => (failed_checks, sequence, event_type),
        other => panic!("expected SealedObjectVerify, got {other:?}"),
    }
}

#[test]
fn unseal_roundtrip_own_ceremony_btn() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let sealed = rt
        .seal(
            "obj.invoice.v1",
            fields(&[("amount", json!(9800)), ("customer", json!("acme"))]),
            &no_receipt(),
        )
        .unwrap();
    let out = rt.unseal(&sealed.wire, &UnsealOptions::default()).unwrap();

    // Exact: the tn_sealed wire marker must NOT leak into user fields.
    assert_eq!(
        out.fields,
        fields(&[("amount", json!(9800)), ("customer", json!("acme"))])
    );
    assert!(out.hidden_groups.is_empty());
    assert!(out.sealed_blocks.is_empty());
    assert!(out.valid.signature);
    assert!(out.valid.row_hash);
    // The raw envelope stays wire-faithful (keeps the marker).
    assert_eq!(out.envelope["tn_sealed"], json!(1));
    assert_eq!(out.plaintext["default"]["amount"], json!(9800));
}

#[test]
fn unseal_verify_false_returns_despite_tamper() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let sealed = rt
        .seal("obj.test.v1", fields(&[("x", json!(1))]), &no_receipt())
        .unwrap();
    let mut env = sealed.envelope.clone();
    env.insert("tn_sealed".into(), json!(2));
    let tampered = serde_json::to_string(&Value::Object(env)).unwrap();

    let out = rt
        .unseal(
            &tampered,
            &UnsealOptions {
                verify: false,
                ..UnsealOptions::default()
            },
        )
        .unwrap();
    assert_eq!(out.envelope["event_type"], json!("obj.test.v1"));
    // verify=false reports both checks unverified (mirrors Python).
    assert!(!out.valid.signature);
    assert!(!out.valid.row_hash);
    // The block still opens — decryption is independent of verification.
    assert_eq!(out.fields["x"], json!(1));
}

#[test]
fn unseal_tampered_public_raises_verify() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let sealed = rt
        .seal("obj.test.v1", fields(&[("x", json!(1))]), &no_receipt())
        .unwrap();
    let mut env = sealed.envelope.clone();
    env.insert("tn_sealed".into(), json!(2));
    let tampered = serde_json::to_string(&Value::Object(env)).unwrap();

    let err = rt.unseal(&tampered, &UnsealOptions::default()).unwrap_err();
    let (failed, sequence, event_type) = assert_verify_err(err);
    assert_eq!(failed, vec!["row_hash".to_string()]);
    assert_eq!(sequence, 0);
    assert_eq!(event_type, "obj.test.v1");
}

#[test]
fn unseal_tampered_ciphertext_raises_verify() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let sealed = rt
        .seal("obj.test.v1", fields(&[("x", json!(1))]), &no_receipt())
        .unwrap();
    let mut env = sealed.envelope.clone();
    let block = env["default"].as_object().unwrap().clone();
    let ct = block["ciphertext"].as_str().unwrap().to_string();
    let tail = if &ct[ct.len() - 4..] == "AAAA" {
        "BBBB"
    } else {
        "AAAA"
    };
    let mut new_block = block;
    new_block.insert(
        "ciphertext".into(),
        json!(format!("{}{}", &ct[..ct.len() - 4], tail)),
    );
    env.insert("default".into(), Value::Object(new_block));
    let tampered = serde_json::to_string(&Value::Object(env)).unwrap();

    let err = rt.unseal(&tampered, &UnsealOptions::default()).unwrap_err();
    let (failed, _, _) = assert_verify_err(err);
    assert_eq!(failed, vec!["row_hash".to_string()]);
}

#[test]
fn unseal_swapped_signature_fails_signature_check_only() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let sealed = rt
        .seal("obj.test.v1", fields(&[("x", json!(1))]), &no_receipt())
        .unwrap();
    let other = rt
        .seal("obj.other.v1", fields(&[("y", json!(2))]), &no_receipt())
        .unwrap();

    // A validly-encoded signature from a different object: row_hash
    // still recomputes, so only the signature check trips.
    let mut env = sealed.envelope.clone();
    env.insert("signature".into(), other.envelope["signature"].clone());
    let tampered = serde_json::to_string(&Value::Object(env)).unwrap();

    let err = rt.unseal(&tampered, &UnsealOptions::default()).unwrap_err();
    let (failed, _, _) = assert_verify_err(err);
    assert_eq!(failed, vec!["signature".to_string()]);
}

#[test]
fn unseal_malformed_sources_raise_malformed() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    // Mirror the Python param set end-to-end through the runtime verb.
    let cases: &[&str] = &[
        "not json at all",
        "[1,2,3]",
        "{}",
        r#"{"device_identity":"d","event_type":"x","row_hash":"h","signature":"s"}"#,
    ];
    for bad in cases {
        let err = rt.unseal(bad, &UnsealOptions::default()).unwrap_err();
        match err {
            Error::Malformed { kind, .. } => assert_eq!(kind, "sealed object", "case={bad}"),
            other => panic!("case={bad}: expected Malformed, got {other:?}"),
        }
    }
}

#[test]
fn unseal_no_key_returns_public_frame() {
    let td_a = tempfile::tempdir().unwrap();
    let cer_a = setup_minimal_btn_ceremony(td_a.path());
    let rt_a = Runtime::init(&cer_a.yaml_path).unwrap();
    let sealed = rt_a
        .seal(
            "obj.memo.v1",
            fields(&[("body", json!("private"))]),
            &no_receipt(),
        )
        .unwrap();

    // A second, unrelated ceremony holds no fitting key: no error, the
    // verified public frame comes back with the block still sealed.
    // (Runtime::ephemeral mints RANDOM btn material; the shared test
    // helper pins a fixed seed, which would make "unrelated" ceremonies
    // share keys and defeat this test.)
    let rt_b = Runtime::ephemeral().unwrap();

    let out = rt_b
        .unseal(&sealed.wire, &UnsealOptions::default())
        .unwrap();
    assert!(out.valid.signature && out.valid.row_hash);
    assert_eq!(out.hidden_groups, vec!["default".to_string()]);
    assert_eq!(out.sealed_blocks.len(), 1);
    assert_eq!(out.sealed_blocks[0].name, "default");
    assert_eq!(
        out.sealed_blocks[0].ciphertext_b64,
        sealed.envelope["default"]["ciphertext"].as_str().unwrap()
    );
    assert_eq!(out.sealed_blocks[0].aad_b64, "");
    assert!(!out.fields.contains_key("body"));
    assert!(out.plaintext.is_empty());
}

#[test]
fn unseal_aad_binds_and_roundtrips() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let mut aad = Map::new();
    aad.insert("case".to_string(), json!("A-17"));
    let sealed = rt
        .seal(
            "obj.test.v1",
            fields(&[("x", json!(1))]),
            &SealOptions {
                receipt: false,
                aad,
            },
        )
        .unwrap();

    // Authenticated public echo present, and the object opens
    // (aad_bytes_for reconstructs the binding for decrypt).
    assert!(sealed.envelope.contains_key("tn_aad"));
    let out = rt.unseal(&sealed.wire, &UnsealOptions::default()).unwrap();
    assert_eq!(out.fields["x"], json!(1));

    // The echo is bound into row_hash: tampering it fails verify.
    let mut env = sealed.envelope.clone();
    let echo = env["tn_aad"].as_str().unwrap().replace("A-17", "B-99");
    env.insert("tn_aad".into(), json!(echo));
    let tampered = serde_json::to_string(&Value::Object(env)).unwrap();
    let err = rt.unseal(&tampered, &UnsealOptions::default()).unwrap_err();
    let (failed, _, _) = assert_verify_err(err);
    assert!(failed.contains(&"row_hash".to_string()));
}

#[test]
fn unseal_as_recipient_single_kit() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    // Mint a kit for reader B via the admin verb, dropped into a bare
    // directory under the canonical <group>.btn.mykit name.
    let bare = td.path().join("bob-keys");
    std::fs::create_dir_all(&bare).unwrap();
    rt.admin_add_recipient(
        "default",
        &bare.join("default.btn.mykit"),
        Some("did:key:zBobStub"),
    )
    .unwrap();

    let sealed = rt
        .seal("obj.memo.v1", fields(&[("x", json!(1))]), &no_receipt())
        .unwrap();

    // Bring-your-own-kit against the bare dir; no runtime needed.
    let out = unseal_as_recipient(&sealed.wire, &bare, "default", true).unwrap();
    assert_eq!(out.fields, fields(&[("x", json!(1))]));
    assert!(out.hidden_groups.is_empty());
    assert!(out.valid.signature && out.valid.row_hash);

    // A group with no block in the envelope opens nothing and loads
    // nothing — empty plaintext, block reported sealed.
    let out2 = unseal_as_recipient(&sealed.wire, &bare, "partners", true).unwrap();
    assert!(out2.plaintext.is_empty());
    assert_eq!(out2.hidden_groups, vec!["default".to_string()]);

    // No key file of any cipher for the requested group: typed error
    // with the Python message shape.
    let empty = td.path().join("empty-keys");
    std::fs::create_dir_all(&empty).unwrap();
    let err = unseal_as_recipient(&sealed.wire, &empty, "default", true).unwrap_err();
    match err {
        Error::InvalidConfig(msg) => {
            assert!(msg.contains("no recipient key found for group"), "{msg}");
            assert!(msg.contains("Looked for"), "{msg}");
        }
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
}

#[test]
fn unseal_pre_rotation_object_after_rotation_btn() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let sealed = rt
        .seal("obj.test.v1", fields(&[("x", json!(1))]), &no_receipt())
        .unwrap();
    rt.admin_rotate_group("default").unwrap();

    // Rotation archives the prior self-kit as .btn.mykit.retired.<epoch>;
    // the retired-kit walk still opens the pre-rotation object.
    let out = rt.unseal(&sealed.wire, &UnsealOptions::default()).unwrap();
    assert_eq!(out.fields["x"], json!(1));
    assert!(out.hidden_groups.is_empty());
}

#[cfg(feature = "hibe")]
#[test]
fn unseal_keybag_two_ciphers_one_group() {
    use rand_core::OsRng;

    // Authority: a hibe ceremony sealing into group "default".
    let td_a = tempfile::tempdir().unwrap();
    let keystore_a = td_a.path().join(".tn").join("keys");
    std::fs::create_dir_all(&keystore_a).unwrap();
    let dk = DeviceKey::generate();
    std::fs::write(keystore_a.join("local.private"), dk.private_bytes()).unwrap();
    std::fs::write(keystore_a.join("index_master.key"), [0x11u8; 32]).unwrap();
    let (pp, msk) = tn_hibe::setup(4, OsRng).unwrap();
    let id_path = "acme/objects";
    std::fs::write(keystore_a.join("default.hibe.mpk"), pp.to_bytes()).unwrap();
    std::fs::write(keystore_a.join("default.hibe.idpath"), id_path.as_bytes()).unwrap();
    std::fs::write(keystore_a.join("default.hibe.msk"), msk.to_bytes()).unwrap();
    let did = dk.did().to_string();
    let yaml = format!(
        "ceremony: {{id: cer_hibe, mode: local, cipher: hibe, protocol_events_location: main_log}}\n\
         keystore: {{path: ./.tn/keys}}\n\
         device: {{device_identity: \"{did}\"}}\n\
         public_fields: []\n\
         default_policy: private\n\
         groups:\n\
         \x20 default:\n\
         \x20   policy: private\n\
         \x20   cipher: hibe\n\
         \x20   index_epoch: 0\n\
         fields: {{}}\n\
         llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n",
    );
    let yaml_a = td_a.path().join("tn.yaml");
    std::fs::write(&yaml_a, yaml).unwrap();
    let rt_a = Runtime::init(&yaml_a).unwrap();
    let sealed = rt_a
        .seal(
            "obj.gov.v1",
            fields(&[("secret", json!("s3"))]),
            &no_receipt(),
        )
        .unwrap();

    // Reader: own btn ceremony PLUS an absorbed hibe grant for the SAME
    // group name — the bag must hold both candidates and open via hibe.
    let td_b = tempfile::tempdir().unwrap();
    let cer_b = setup_minimal_btn_ceremony(td_b.path());
    let sk = tn_hibe::keygen(&pp, &msk, &tn_hibe::Identity::from_str_path(id_path), OsRng).unwrap();
    std::fs::write(cer_b.keystore.join("default.hibe.mpk"), pp.to_bytes()).unwrap();
    std::fs::write(
        cer_b.keystore.join("default.hibe.idpath"),
        id_path.as_bytes(),
    )
    .unwrap();
    std::fs::write(cer_b.keystore.join("default.hibe.sk"), sk.to_bytes()).unwrap();
    let rt_b = Runtime::init(&cer_b.yaml_path).unwrap();

    let out = rt_b
        .unseal(&sealed.wire, &UnsealOptions::default())
        .unwrap();
    assert_eq!(out.fields["secret"], json!("s3"));
    assert!(out.hidden_groups.is_empty());
}

#[test]
#[cfg(not(feature = "native-jwe"))]
fn unseal_jwe_block_reported_as_sealed_candidate() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    // A jwe recipient key for "default" lives in the keystore, but this build
    // omitted native JWE and must surface it for a managed second-pass decrypt.
    std::fs::write(cer.keystore.join("default.jwe.mykey"), b"jwe-key-stub").unwrap();
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    // Hand-built envelope whose default block carries arbitrary bytes,
    // with a tn_aad echo for the group.
    let env = json!({
        "device_identity": "did:key:zForeign",
        "timestamp": "2026-07-09T00:00:00.000000Z",
        "event_id": "00000000-0000-4000-8000-0000000000bb",
        "event_type": "obj.jwe.v1",
        "level": "",
        "sequence": 0,
        "prev_hash": "",
        "row_hash": "sha256:0000",
        "signature": "sig",
        "tn_aad": "{\"default\":{\"case\":\"A-17\"}}",
        "tn_sealed": 1,
        "default": {"ciphertext": STANDARD.encode(b"opaque-jwe-bytes"), "field_hashes": {}},
    });
    let text = serde_json::to_string(&env).unwrap();

    let out = rt
        .unseal(
            &text,
            &UnsealOptions {
                verify: false,
                ..UnsealOptions::default()
            },
        )
        .unwrap();
    assert_eq!(out.hidden_groups, vec!["default".to_string()]);
    assert_eq!(out.sealed_blocks.len(), 1);
    let block = &out.sealed_blocks[0];
    assert_eq!(block.name, "default");
    assert_eq!(block.keystore_candidates, vec!["jwe".to_string()]);
    // aad_b64 is base64(canonical_bytes(this group's marker)) — the
    // managed cipher's second pass needs byte-identical AAD.
    assert_eq!(block.aad_b64, STANDARD.encode(b"{\"case\":\"A-17\"}"));
}
