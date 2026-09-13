#![cfg(all(feature = "fs", feature = "native-jwe", not(target_arch = "wasm32")))]
use base64::Engine;
use tn_core::governed::{Governance, UseContext};
use tn_core::providers::*;
use tn_core::runtime::Objects;

const POLICY: &str = "## hello.message\n### instruction\nRead a greeting.\n### use_for\nGreeting.\n### do_not_use_for\nOther use.\n### consequences\nReview.\n### on_violation_or_error\nStop.\n";

#[test]
fn persisted_btn_and_jwe_reopen_exact_material_and_real_ciphertext() {
    for cipher in ["btn", "jwe", "hibe"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys.json");
        let store = FileKeyStore::create(&path, "hello", &["messages"], cipher).unwrap();
        let identity = IdentityProvider::resolve(&store, "hello").unwrap();
        let objects = Objects::from_capabilities(
            identity.clone(),
            KeyProvider::resolve(&store, &identity).unwrap(),
            None,
        )
        .unwrap();
        let policy =
            Governance::from_markdown(identity.did(), POLICY, "agents.md", "hello.message")
                .unwrap();
        let data = objects
            .create_selected(
                serde_json::json!({"message":"Hello, world!"}),
                policy,
                "messages",
            )
            .unwrap();
        let wire = data.forward().unwrap().to_vec();
        drop(objects);
        drop(store);
        let original = std::fs::read(&path).unwrap();
        assert!(FileKeyStore::create(&path, "hello", &["messages"], cipher).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let store = FileKeyStore::open(&path).unwrap();
        let reopened = IdentityProvider::resolve(&store, "hello").unwrap();
        assert_eq!(reopened.did(), identity.did());
        let objects = Objects::from_capabilities(
            reopened,
            KeyProvider::resolve(&store, &identity).unwrap(),
            None,
        )
        .unwrap();
        let received = objects
            .receive_for(
                std::str::from_utf8(&wire).unwrap(),
                &UseContext::new("hello", "greeting", "read").unwrap(),
                ["messages"],
                None,
                |context| Ok(context.object().writer() == identity.did()),
            )
            .unwrap();
        assert_eq!(
            received.get("messages", Some("message")).unwrap(),
            "Hello, world!"
        );
        let envelope: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        for name in ["messages", "tn.agents"] {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(envelope[name]["ciphertext"].as_str().unwrap())
                .unwrap();
            if cipher == "btn" {
                assert!(tn_btn::Ciphertext::from_bytes(&raw).is_ok());
            } else if cipher == "hibe" {
                assert!(!raw.is_empty()); // Full native authenticated open is asserted above.
            } else {
                let jwe: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(jwe["protected"].as_str().unwrap())
                    .unwrap();
                let header: serde_json::Value = serde_json::from_slice(&header).unwrap();
                assert_eq!(header["enc"], "A256GCM");
                assert!(jwe["recipients"].as_array().unwrap().len() == 1);
                assert!(jwe["aad"].is_string());
            }
        }
        let wrong = FileKeyStore::create(
            &directory.path().join("other.json"),
            "other",
            &["messages"],
            cipher,
        )
        .unwrap();
        let other = IdentityProvider::resolve(&wrong, "other").unwrap();
        assert!(KeyProvider::resolve(&store, &other).is_err());
        let wrong_objects = Objects::from_capabilities(
            other.clone(),
            KeyProvider::resolve(&wrong, &other).unwrap(),
            None,
        )
        .unwrap();
        assert!(wrong_objects
            .receive_for(
                std::str::from_utf8(&wire).unwrap(),
                &UseContext::new("other", "greeting", "read").unwrap(),
                ["messages"],
                None,
                |_| Ok(true)
            )
            .is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}

#[test]
fn keystore_errors_never_generate_replacement_keys() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("keys.json");
    assert!(FileKeyStore::open(&path).is_err());
    assert!(!path.exists());
    assert!(FileKeyStore::create(&path, "hello", &["messages"], "fake").is_err());
    assert!(!path.exists());
    std::fs::write(&path, b"broken").unwrap();
    assert!(FileKeyStore::open(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"broken");
}
