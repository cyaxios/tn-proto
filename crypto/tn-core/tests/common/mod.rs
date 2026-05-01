//! Shared test helpers: set up a minimal btn ceremony with publisher + reader roles.
//!
//! Reused by runtime_init, emit, read, chain, and close tests (Tasks 21–29).

#![allow(dead_code)] // not all tests use every helper

use std::path::{Path, PathBuf};

/// Handle returned by `setup_minimal_btn_ceremony`.
pub struct BtnCeremony {
    /// Absolute path to the tn.yaml written into `root`.
    pub yaml_path: PathBuf,
    /// Absolute path to the keystore directory inside `root`.
    pub keystore: PathBuf,
    /// The `did:key:z…` of the device key created for this ceremony.
    pub did: String,
}

/// Create a btn ceremony at `root` where the single party is both publisher
/// (via `default.btn.state`) and self-reader (via `default.btn.mykit`).
///
/// Layout written to disk:
/// ```text
/// <root>/
///   .tn/
///     keys/
///       local.private         (32-byte Ed25519 seed)
///       index_master.key      (32 bytes, all 0x11)
///       default.btn.state     (serialized PublisherState)
///       default.btn.mykit     (minted ReaderKit bytes)
///   tn.yaml
/// ```
pub fn setup_minimal_btn_ceremony(root: &Path) -> BtnCeremony {
    let keystore = root.join(".tn").join("keys");
    std::fs::create_dir_all(&keystore).unwrap();

    // Device key — generate and persist raw 32-byte seed.
    let dk = tn_core::DeviceKey::generate();
    std::fs::write(keystore.join("local.private"), dk.private_bytes()).unwrap();

    // Master index key (32 bytes).
    std::fs::write(keystore.join("index_master.key"), [0x11u8; 32]).unwrap();

    // btn publisher state + self-reader kit.
    let mut pub_state =
        tn_btn::PublisherState::setup_with_seed(tn_btn::Config, [0x22u8; 32]).unwrap();
    let kit = pub_state.mint().unwrap();
    std::fs::write(keystore.join("default.btn.state"), pub_state.to_bytes()).unwrap();
    std::fs::write(keystore.join("default.btn.mykit"), kit.to_bytes()).unwrap();

    // tn.yaml — inline format; uses flow-style mappings for compact output.
    let did = dk.did().to_string();
    let yaml = format!(
        "ceremony: {{id: cer_test, mode: local, cipher: btn, protocol_events_location: main_log}}\n\
         keystore: {{path: ./.tn/keys}}\n\
         me: {{did: \"{did}\"}}\n\
         public_fields: []\n\
         default_policy: private\n\
         groups:\n\
         \x20 default:\n\
         \x20   policy: private\n\
         \x20   cipher: btn\n\
         \x20   recipients:\n\
         \x20     - {{did: \"{did}\"}}\n\
         \x20   index_epoch: 0\n\
         fields: {{}}\n\
         llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n",
    );
    let yaml_path = root.join("tn.yaml");
    std::fs::write(&yaml_path, yaml).unwrap();

    BtnCeremony {
        yaml_path,
        keystore,
        did,
    }
}

/// Like `setup_minimal_btn_ceremony`, but mints a larger reader pool and
/// applies `n_revocations` revocations (leaves 0..n_revocations) to the
/// publisher state before persisting it. The self-reader kit is at leaf N,
/// so `n_revocations < N`. N defaults to 240 (safe at h=8 where MAX=256).
///
/// Used by perf-matrix tests to measure how revocation count affects
/// ciphertext size and encrypt throughput.
pub fn setup_minimal_btn_ceremony_with_revocations(
    root: &Path,
    n_revocations: usize,
) -> BtnCeremony {
    const TOTAL_READERS: usize = 240;
    assert!(
        n_revocations < TOTAL_READERS,
        "n_revocations {n_revocations} must be < {TOTAL_READERS}"
    );

    let keystore = root.join(".tn").join("keys");
    std::fs::create_dir_all(&keystore).unwrap();

    let dk = tn_core::DeviceKey::generate();
    std::fs::write(keystore.join("local.private"), dk.private_bytes()).unwrap();
    std::fs::write(keystore.join("index_master.key"), [0x11u8; 32]).unwrap();

    let mut pub_state =
        tn_btn::PublisherState::setup_with_seed(tn_btn::Config, [0x22u8; 32]).unwrap();
    // Mint TOTAL_READERS kits; keep the last one as our self-reader.
    let mut kits = Vec::with_capacity(TOTAL_READERS);
    for _ in 0..TOTAL_READERS {
        kits.push(pub_state.mint().unwrap());
    }
    let self_kit = kits.pop().unwrap();
    // Revoke leaves 0..n_revocations.
    for i in 0..n_revocations {
        pub_state
            .revoke_by_leaf(tn_btn::LeafIndex(i as u64))
            .unwrap();
    }

    std::fs::write(keystore.join("default.btn.state"), pub_state.to_bytes()).unwrap();
    std::fs::write(keystore.join("default.btn.mykit"), self_kit.to_bytes()).unwrap();

    let did = dk.did().to_string();
    let yaml = format!(
        "ceremony: {{id: cer_perf, mode: local, cipher: btn, protocol_events_location: main_log}}\n\
         keystore: {{path: ./.tn/keys}}\n\
         me: {{did: \"{did}\"}}\n\
         public_fields: []\n\
         default_policy: private\n\
         groups:\n\
         \x20 default:\n\
         \x20   policy: private\n\
         \x20   cipher: btn\n\
         \x20   recipients:\n\
         \x20     - {{did: \"{did}\"}}\n\
         \x20   index_epoch: 0\n\
         fields: {{}}\n\
         llm_classifier: {{enabled: false, provider: \"\", model: \"\"}}\n",
    );
    let yaml_path = root.join("tn.yaml");
    std::fs::write(&yaml_path, yaml).unwrap();

    BtnCeremony {
        yaml_path,
        keystore,
        did,
    }
}
