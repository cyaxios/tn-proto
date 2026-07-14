//! Integration tests for the hibe admin verbs: `Runtime::admin_grant_reader`
//! (HIBE's add_recipient) and `Runtime::admin_rotate_id_path` (the
//! policy-path rotation). Mirrors the Python normative contracts in
//! `tn/admin/__init__.py::grant_reader` / `rotate_reader_path` and
//! `tn/cipher.py::HibeGroupCipher.rotate_id_path`, including the on-disk
//! keystore artifacts a Python authority must be able to open.

#![cfg(all(feature = "fs", feature = "hibe"))]

mod common;

use std::path::{Path, PathBuf};

use rand_core::OsRng;
use serde_json::{json, Map, Value};

use common::setup_minimal_btn_ceremony;
use tn_core::runtime::unseal_as_recipient;
use tn_core::{AbsorbSource, Error, Runtime, SealOptions, UnsealOptions};

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

/// A hibe authority ceremony: device key + index key + the authority key
/// files (`default.hibe.{mpk,idpath,msk}` — no reader `sk`, the msk mints
/// keys on demand). Mirrors `seal_unseal.rs::unseal_keybag_two_ciphers_one_group`.
struct HibeCeremony {
    yaml_path: PathBuf,
    keystore: PathBuf,
    pp: tn_hibe::PublicParams,
    msk: tn_hibe::MasterKey,
}

fn setup_hibe_authority(root: &Path, id_path: &str) -> HibeCeremony {
    let keystore = root.join(".tn").join("keys");
    std::fs::create_dir_all(&keystore).unwrap();
    let dk = tn_core::DeviceKey::generate();
    std::fs::write(keystore.join("local.private"), dk.private_bytes()).unwrap();
    std::fs::write(keystore.join("index_master.key"), [0x11u8; 32]).unwrap();
    let (pp, msk) = tn_hibe::setup(4, OsRng).unwrap();
    std::fs::write(keystore.join("default.hibe.mpk"), pp.to_bytes()).unwrap();
    std::fs::write(keystore.join("default.hibe.idpath"), id_path.as_bytes()).unwrap();
    std::fs::write(keystore.join("default.hibe.msk"), msk.to_bytes()).unwrap();
    let did = dk.did().to_string();
    let yaml = format!(
        "ceremony: {{id: cer_hibe_admin, mode: local, cipher: hibe, protocol_events_location: main_log}}\n\
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
    let yaml_path = root.join("tn.yaml");
    std::fs::write(&yaml_path, yaml).unwrap();
    HibeCeremony {
        yaml_path,
        keystore,
        pp,
        msk,
    }
}

/// Bare recipient key directory for `unseal_as_recipient`: mpk + idpath +
/// an msk-minted key for `key_path`. `idpath` is what this reader believes
/// the group currently seals to (drives ancestor derivation).
fn write_reader_dir(root: &Path, cer: &HibeCeremony, idpath: &str, key_path: &str) -> PathBuf {
    let dir = root.to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    let sk = tn_hibe::keygen(
        &cer.pp,
        &cer.msk,
        &tn_hibe::Identity::from_str_path(key_path),
        OsRng,
    )
    .unwrap();
    std::fs::write(dir.join("default.hibe.mpk"), cer.pp.to_bytes()).unwrap();
    std::fs::write(dir.join("default.hibe.idpath"), idpath.as_bytes()).unwrap();
    std::fs::write(dir.join("default.hibe.sk"), sk.to_bytes()).unwrap();
    dir
}

// ---------------------------------------------------------------------------
// grant leg
// ---------------------------------------------------------------------------

#[test]
fn grant_reader_rejects_missing_or_noncanonical_did_before_staging() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_hibe_authority(td.path(), "acme/objects");
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    for (name, did) in [
        ("missing", None),
        ("abbreviated", Some("did:key:z6Mk-reader")),
    ] {
        let out = td.path().join(format!("{name}.tnpkg"));
        let error = rt
            .admin_grant_reader("default", did, &out, None)
            .expect_err("normal grants require a complete Ed25519 did:key");
        assert!(error.to_string().contains("Ed25519 did:key"), "{error}");
        assert!(!out.exists());
    }
    assert!(!cer.keystore.join("default.hibe.grants").exists());
}

#[test]
fn grant_reader_kit_absorbs_and_opens_sealed_content() {
    let td_a = tempfile::tempdir().unwrap();
    let cer = setup_hibe_authority(td_a.path(), "acme/objects");
    let rt = Runtime::init(&cer.yaml_path).unwrap();
    let sealed = rt
        .seal(
            "obj.gov.v1",
            fields(&[("secret", json!("granted-only"))]),
            &no_receipt(),
        )
        .unwrap();

    // Reader: own btn ceremony; its real did:key makes the kit
    // recipient-sealed (Python parity: seal iff the DID resolves).
    let td_b = tempfile::tempdir().unwrap();
    let cer_b = setup_minimal_btn_ceremony(td_b.path());
    let kit_path = td_a.path().join("reader.tnpkg");
    let result = rt
        .admin_grant_reader("default", Some(&cer_b.device_identity), &kit_path, None)
        .unwrap();
    assert_eq!(result.group, "default");
    assert_eq!(
        result.reader_did.as_deref(),
        Some(cer_b.device_identity.as_str())
    );
    assert_eq!(result.id_path, "acme/objects");
    assert!(kit_path.exists());
    assert_eq!(result.path, kit_path);

    // The grant registry records who was granted which path.
    let grants: Vec<Value> =
        serde_json::from_slice(&std::fs::read(cer.keystore.join("default.hibe.grants")).unwrap())
            .unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0]["reader_did"], json!(cer_b.device_identity));
    assert_eq!(grants[0]["id_path"], json!("acme/objects"));

    // The authority master secret never rides a kit.
    let bytes = std::fs::read(&kit_path).unwrap();
    let (manifest, body) =
        tn_core::tnpkg::read_tnpkg_verified(tn_core::tnpkg::TnpkgSource::Bytes(&bytes)).unwrap();
    assert!(manifest
        .state
        .as_ref()
        .and_then(|state| state.get("body_encryption"))
        .is_some());
    assert!(body.contains_key("body/encrypted.bin"));
    assert!(!body.contains_key("body/default.hibe.sk"));
    let mut zf = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let names: Vec<String> = (0..zf.len())
        .map(|i| zf.by_index(i).unwrap().name().to_string())
        .collect();
    assert!(
        !names.iter().any(|n| n.ends_with(".hibe.msk")),
        "msk must never ride a kit: {names:?}"
    );

    // A different device cannot unwrap or install the bearer capability.
    let td_c = tempfile::tempdir().unwrap();
    let cer_c = setup_minimal_btn_ceremony(td_c.path());
    let rt_c = Runtime::init(&cer_c.yaml_path).unwrap();
    let rejected = rt_c.absorb(AbsorbSource::Path(&kit_path)).unwrap();
    assert_eq!(rejected.legacy_status, "rejected");
    assert!(rejected.legacy_reason.contains("sealed-box wrap"));

    // Reader absorbs the kit and opens the sealed object via the key bag.
    let rt_b = Runtime::init(&cer_b.yaml_path).unwrap();
    let receipt = rt_b.absorb(AbsorbSource::Path(&kit_path)).unwrap();
    assert_eq!(receipt.kind, "kit_bundle", "{receipt:?}");
    assert!(cer_b.keystore.join("default.hibe.sk").exists());
    let out = rt_b
        .unseal(&sealed.wire, &UnsealOptions::default())
        .unwrap();
    assert_eq!(out.fields["secret"], json!("granted-only"));
    assert!(out.hidden_groups.is_empty());
}

#[test]
fn grant_reader_custom_ancestor_id_path_derives_down() {
    let td_a = tempfile::tempdir().unwrap();
    let cer = setup_hibe_authority(td_a.path(), "acme/objects");
    let rt = Runtime::init(&cer.yaml_path).unwrap();
    let sealed = rt
        .seal(
            "obj.gov.v1",
            fields(&[("secret", json!("s3"))]),
            &no_receipt(),
        )
        .unwrap();

    // Use the explicitly unsafe compatibility path for a stub DID so the
    // delegated ancestor key remains inspectable in this boundary test.
    let stub_kit = td_a.path().join("dept-stub.tnpkg");
    let result = rt
        .admin_grant_reader_unsafe_plaintext(
            "default",
            Some("did:key:z6Mk-dept"),
            &stub_kit,
            Some("acme"),
        )
        .unwrap();
    assert_eq!(result.id_path, "acme");

    // The staged sk is keyed to the ancestor path, and the kit idpath file
    // still carries the group's sealing path (Python grant_reader parity).
    let bytes = std::fs::read(&stub_kit).unwrap();
    let mut zf = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let mut staged_sk = Vec::new();
    let mut staged_idpath = Vec::new();
    for i in 0..zf.len() {
        use std::io::Read as _;
        let mut entry = zf.by_index(i).unwrap();
        if entry.name().ends_with("default.hibe.sk") {
            entry.read_to_end(&mut staged_sk).unwrap();
        } else if entry.name().ends_with("default.hibe.idpath") {
            entry.read_to_end(&mut staged_idpath).unwrap();
        }
    }
    let staged_key = tn_hibe::PrivateKey::from_bytes(&staged_sk).unwrap();
    assert_eq!(
        staged_key.identity(),
        &tn_hibe::Identity::from_str_path("acme")
    );
    assert_eq!(staged_idpath, b"acme/objects");

    let grants: Vec<Value> =
        serde_json::from_slice(&std::fs::read(cer.keystore.join("default.hibe.grants")).unwrap())
            .unwrap();
    assert_eq!(grants[0]["id_path"], json!("acme"));

    // Same custom-path grant, recipient-sealed to a real reader ceremony:
    // the absorbed ancestor key opens content sealed to the deeper path.
    let td_b = tempfile::tempdir().unwrap();
    let cer_b = setup_minimal_btn_ceremony(td_b.path());
    let kit_path = td_a.path().join("dept-reader.tnpkg");
    rt.admin_grant_reader(
        "default",
        Some(&cer_b.device_identity),
        &kit_path,
        Some("acme"),
    )
    .unwrap();
    let rt_b = Runtime::init(&cer_b.yaml_path).unwrap();
    rt_b.absorb(AbsorbSource::Path(&kit_path)).unwrap();
    let out = rt_b
        .unseal(&sealed.wire, &UnsealOptions::default())
        .unwrap();
    assert_eq!(out.fields["secret"], json!("s3"));
}

#[test]
fn grant_reader_rejects_invalid_custom_id_path() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_hibe_authority(td.path(), "acme/objects");
    let rt = Runtime::init(&cer.yaml_path).unwrap();
    let err = rt
        .admin_grant_reader_unsafe_plaintext(
            "default",
            Some("did:key:zR"),
            &td.path().join("x.tnpkg"),
            Some("acme//objects"),
        )
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("must not contain empty path segments"),
        "{msg}"
    );
    // Nothing staged, nothing recorded.
    assert!(!cer.keystore.join("default.hibe.grants").exists());
}

#[test]
fn grant_reader_is_hibe_only() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();
    let err = rt
        .admin_grant_reader(
            "default",
            Some("did:key:zR"),
            &td.path().join("x.tnpkg"),
            None,
        )
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("grant_reader is hibe-only. BTN uses admin_add_recipient; JWE uses authenticated public-key enrollment."),
        "{msg}"
    );

    let err = rt
        .admin_grant_reader("nope", Some("did:key:zR"), &td.path().join("x.tnpkg"), None)
        .unwrap_err();
    assert!(err.to_string().contains("unknown group"), "{err}");
}

#[test]
fn grant_records_match_python_grants_file_format() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_hibe_authority(td.path(), "acme/objects");
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    rt.admin_grant_reader_unsafe_plaintext(
        "default",
        Some("did:key:z6Mk-reader-one"),
        &td.path().join("one.tnpkg"),
        None,
    )
    .unwrap();
    rt.admin_grant_reader_unsafe_plaintext(
        "default",
        Some("did:key:z6Mk-reader-two"),
        &td.path().join("two.tnpkg"),
        None,
    )
    .unwrap();
    // Re-granting an existing reader replaces their row (moves to the end),
    // exactly like Python's _hibe_grants_update.
    rt.admin_grant_reader_unsafe_plaintext(
        "default",
        Some("did:key:z6Mk-reader-one"),
        &td.path().join("one-again.tnpkg"),
        Some("acme"),
    )
    .unwrap();

    let on_disk = std::fs::read_to_string(cer.keystore.join("default.hibe.grants")).unwrap();
    // Byte parity with Python `json.dumps(grants, indent=1)` (LF form —
    // Python's own writer newline-translates on Windows, so parity is
    // asserted on the LF-normalized bytes).
    let expected = "[\n \
                    {\n  \
                    \"reader_did\": \"did:key:z6Mk-reader-two\",\n  \
                    \"id_path\": \"acme/objects\"\n \
                    },\n \
                    {\n  \
                    \"reader_did\": \"did:key:z6Mk-reader-one\",\n  \
                    \"id_path\": \"acme\"\n \
                    }\n]";
    assert_eq!(on_disk.replace("\r\n", "\n"), expected);
}

// ---------------------------------------------------------------------------
// rotate leg
// ---------------------------------------------------------------------------

#[test]
fn rotate_id_path_moves_future_seals_without_reinit() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_hibe_authority(td.path(), "acme/objects");
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    let old_sk_missing = !cer.keystore.join("default.hibe.sk").exists();
    assert!(old_sk_missing, "authority fixture holds no reader sk");

    let sealed_before = rt
        .seal("obj.gov.v1", fields(&[("e", json!("one"))]), &no_receipt())
        .unwrap();

    let result = rt
        .admin_rotate_id_path("default", "acme/objects~r1", false)
        .unwrap();
    assert_eq!(result.group, "default");
    assert_eq!(result.previous_path, "acme/objects");
    assert_eq!(result.new_path, "acme/objects~r1");

    // HAZARD (runtime/admin.rs cache): the SAME runtime, no re-init, must
    // seal under the NEW path.
    let sealed_after = rt
        .seal("obj.gov.v1", fields(&[("e", json!("two"))]), &no_receipt())
        .unwrap();

    // A reader keyed ONLY to the old path opens the pre-rotation seal and
    // is locked out of the post-rotation one.
    let old_reader = write_reader_dir(
        &td.path().join("old-reader"),
        &cer,
        "acme/objects",
        "acme/objects",
    );
    let out = unseal_as_recipient(&sealed_before.wire, &old_reader, "default", true).unwrap();
    assert_eq!(out.fields["e"], json!("one"));
    let stale = unseal_as_recipient(&sealed_after.wire, &old_reader, "default", true).unwrap();
    assert_eq!(
        stale.hidden_groups,
        vec!["default".to_string()],
        "post-rotation seal must NOT open under the pre-rotation path — \
         the live runtime kept sealing with a stale cached cipher"
    );

    // A reader keyed to the new path opens the post-rotation seal.
    let new_reader = write_reader_dir(
        &td.path().join("new-reader"),
        &cer,
        "acme/objects~r1",
        "acme/objects~r1",
    );
    let out = unseal_as_recipient(&sealed_after.wire, &new_reader, "default", true).unwrap();
    assert_eq!(out.fields["e"], json!("two"));

    // On-disk artifacts, Python-layout-for-layout (tn/cipher.py
    // rotate_id_path): idpath swapped (no trailing newline), history holds
    // the outgoing path (one per line, LF, trailing newline), and no sk to
    // archive here because the authority fixture held none.
    let idpath = std::fs::read(cer.keystore.join("default.hibe.idpath")).unwrap();
    assert_eq!(idpath, b"acme/objects~r1");
    let history = std::fs::read(cer.keystore.join("default.hibe.idpath.history")).unwrap();
    assert_eq!(history, b"acme/objects\n");
    let archived: Vec<_> = std::fs::read_dir(&cer.keystore)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("default.hibe.sk.previous.")
        })
        .collect();
    assert!(archived.is_empty(), "no sk existed, nothing to archive");

    // The authority itself (fresh init: loader walks history + msk) still
    // opens BOTH epochs.
    let rt2 = Runtime::init(&cer.yaml_path).unwrap();
    let before = rt2
        .unseal(&sealed_before.wire, &UnsealOptions::default())
        .unwrap();
    assert_eq!(before.fields["e"], json!("one"));
    let after = rt2
        .unseal(&sealed_after.wire, &UnsealOptions::default())
        .unwrap();
    assert_eq!(after.fields["e"], json!("two"));
}

#[test]
fn rotate_id_path_archives_held_reader_key() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_hibe_authority(td.path(), "team/policy-a");
    // This authority also holds its own reader key (the solo-ceremony
    // shape Python's create() mints).
    let own_sk = tn_hibe::keygen(
        &cer.pp,
        &cer.msk,
        &tn_hibe::Identity::from_str_path("team/policy-a"),
        OsRng,
    )
    .unwrap()
    .to_bytes();
    std::fs::write(cer.keystore.join("default.hibe.sk"), &own_sk).unwrap();

    let rt = Runtime::init(&cer.yaml_path).unwrap();
    rt.admin_rotate_id_path("default", "team/policy-b", false)
        .unwrap();

    // The superseded key is archived under the Python naming scheme and the
    // active sk is fresh material for the new path.
    let archived: Vec<_> = std::fs::read_dir(&cer.keystore)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("default.hibe.sk.previous."))
        })
        .collect();
    assert_eq!(archived.len(), 1, "{archived:?}");
    assert_eq!(std::fs::read(&archived[0]).unwrap(), own_sk);
    let active = std::fs::read(cer.keystore.join("default.hibe.sk")).unwrap();
    assert_ne!(active, own_sk);
    let active_key = tn_hibe::PrivateKey::from_bytes(&active).unwrap();
    assert_eq!(
        active_key.identity(),
        &tn_hibe::Identity::from_str_path("team/policy-b")
    );

    // Second rotation prepends to the history (newest first) — the exact
    // line order Python's _encode_hibe_history_path writer produces.
    rt.admin_rotate_id_path("default", "team/policy-c", false)
        .unwrap();
    let history =
        std::fs::read_to_string(cer.keystore.join("default.hibe.idpath.history")).unwrap();
    assert_eq!(history, "team/policy-b\nteam/policy-a\n");
}

#[test]
fn rotate_id_path_guards() {
    let td = tempfile::tempdir().unwrap();
    let cer = setup_hibe_authority(td.path(), "acme/objects");
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    // Same-path rejection (Python: ValueError "new path equals the current path").
    let err = rt
        .admin_rotate_id_path("default", "acme/objects", false)
        .unwrap_err();
    assert!(
        err.to_string().contains("new path equals the current path"),
        "{err}"
    );

    // Root path requires the explicit flag (Python _normalize_hibe_path).
    let err = rt.admin_rotate_id_path("default", "", false).unwrap_err();
    assert!(err.to_string().contains("must not be blank"), "{err}");

    // With the flag the boundary passes, but the scheme layer (same one
    // Python calls) rejects a root keygen BEFORE any file is touched.
    let err = rt.admin_rotate_id_path("default", "", true).unwrap_err();
    assert!(matches!(err, Error::Cipher(_)), "{err}");
    assert!(
        !cer.keystore.join("default.hibe.idpath.history").exists(),
        "failed rotation must not leave partial artifacts"
    );
    assert_eq!(
        std::fs::read(cer.keystore.join("default.hibe.idpath")).unwrap(),
        b"acme/objects"
    );

    // Unknown group.
    let err = rt.admin_rotate_id_path("nope", "x/y", false).unwrap_err();
    assert!(err.to_string().contains("unknown group"), "{err}");

    // Malformed new path.
    let err = rt
        .admin_rotate_id_path("default", " padded", false)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("must not have leading or trailing whitespace"),
        "{err}"
    );
}

#[test]
fn rotate_id_path_is_hibe_only_and_authority_only() {
    // btn group: hibe-only guard.
    let td = tempfile::tempdir().unwrap();
    let cer = setup_minimal_btn_ceremony(td.path());
    let rt = Runtime::init(&cer.yaml_path).unwrap();
    let err = rt
        .admin_rotate_id_path("default", "x/y", false)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("this rotation is hibe-only (btn groups rotate via tn rotate)"),
        "{err}"
    );

    // hibe reader-side keystore (no msk): authority-only guard.
    let td2 = tempfile::tempdir().unwrap();
    let cer2 = setup_hibe_authority(td2.path(), "acme/objects");
    let reader_sk = tn_hibe::keygen(
        &cer2.pp,
        &cer2.msk,
        &tn_hibe::Identity::from_str_path("acme/objects"),
        OsRng,
    )
    .unwrap();
    std::fs::write(cer2.keystore.join("default.hibe.sk"), reader_sk.to_bytes()).unwrap();
    std::fs::remove_file(cer2.keystore.join("default.hibe.msk")).unwrap();
    let rt2 = Runtime::init(&cer2.yaml_path).unwrap();
    let err = rt2
        .admin_rotate_id_path("default", "acme/other", false)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("only the authority (msk holder) can rotate the identity path"),
        "{err}"
    );
}

#[test]
fn rotated_keystore_grants_fresh_reader_on_new_path() {
    // grant -> rotate -> grant: the second kit is keyed to the new path,
    // and the grants registry reflects both readers' paths.
    let td = tempfile::tempdir().unwrap();
    let cer = setup_hibe_authority(td.path(), "acme/objects");
    let rt = Runtime::init(&cer.yaml_path).unwrap();

    rt.admin_grant_reader_unsafe_plaintext(
        "default",
        Some("did:key:z6Mk-old"),
        &td.path().join("old.tnpkg"),
        None,
    )
    .unwrap();
    rt.admin_rotate_id_path("default", "acme/objects~r1", false)
        .unwrap();
    rt.admin_grant_reader_unsafe_plaintext(
        "default",
        Some("did:key:z6Mk-new"),
        &td.path().join("new.tnpkg"),
        None,
    )
    .unwrap();

    let grants: Vec<Value> =
        serde_json::from_slice(&std::fs::read(cer.keystore.join("default.hibe.grants")).unwrap())
            .unwrap();
    assert_eq!(grants.len(), 2);
    assert_eq!(grants[0]["id_path"], json!("acme/objects"));
    assert_eq!(grants[1]["id_path"], json!("acme/objects~r1"));
}
