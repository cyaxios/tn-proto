use base64::Engine as _;
use tn_proto::{Identity, IdentitySaveOptions};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn identity_from_mnemonic_is_deterministic_and_derives_vault_wrap_key() -> tn_proto::Result<()> {
    let identity = Identity::from_mnemonic(MNEMONIC, "")?;
    let same = Identity::from_mnemonic(MNEMONIC, "")?;

    assert_eq!(identity.did, same.did);
    assert_eq!(identity.device_priv_b64_enc, same.device_priv_b64_enc);
    assert_eq!(identity.device_pub_b64, same.device_pub_b64);
    assert_eq!(identity.vault_wrap_key()?, same.vault_wrap_key()?);
    assert_eq!(identity.mnemonic(), Some(MNEMONIC));

    let device = identity.device_key()?;
    assert_eq!(identity.did, device.did());
    assert_eq!(
        identity.device_priv_b64_enc,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(device.private_bytes())
    );
    assert_eq!(
        identity.device_pub_b64,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(device.public_bytes())
    );

    Ok(())
}

#[test]
fn identity_rejects_bad_mnemonic_and_bad_word_count() {
    let err = Identity::from_mnemonic("not a real mnemonic", "").unwrap_err();
    assert!(err.to_string().contains("invalid BIP-39 mnemonic"));

    let err = Identity::create_new(13).unwrap_err();
    assert!(err.to_string().contains("word_count"));
}

#[test]
fn identity_save_and_load_roundtrips_python_ts_schema() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("identity.json");
    let mut identity = Identity::from_mnemonic(MNEMONIC, "")?;
    identity.linked_vault = Some("https://vault.example".to_string());
    identity.linked_account_id = Some("acct_123".to_string());
    identity.prefs.default_new_ceremony_mode = "linked".to_string();

    identity.save_with_options(
        &path,
        IdentitySaveOptions {
            keep_mnemonic: true,
        },
    )?;

    let raw: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    assert_eq!(raw["version"].as_u64(), Some(1));
    assert_eq!(raw["did"].as_str(), Some(identity.did.as_str()));
    assert_eq!(raw["device_priv_enc_method"].as_str(), Some("none"));
    assert_eq!(raw["linked_vault"].as_str(), Some("https://vault.example"));
    assert_eq!(raw["linked_account_id"].as_str(), Some("acct_123"));
    assert_eq!(raw["mnemonic_stored"].as_str(), Some(MNEMONIC));
    assert_eq!(
        raw["prefs"]["default_new_ceremony_mode"].as_str(),
        Some("linked")
    );

    let loaded = Identity::load(&path)?;
    assert_eq!(loaded.did, identity.did);
    assert_eq!(
        loaded.device_private_bytes()?,
        identity.device_private_bytes()?
    );
    assert_eq!(loaded.vault_wrap_key()?, identity.vault_wrap_key()?);
    assert_eq!(loaded.mnemonic(), Some(MNEMONIC));
    assert_eq!(loaded.linked_account_id.as_deref(), Some("acct_123"));
    assert_eq!(loaded.prefs.default_new_ceremony_mode.as_str(), "linked");

    Ok(())
}

#[test]
fn identity_save_preserves_unknown_top_level_fields() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("identity.json");
    let mut identity = Identity::from_mnemonic(MNEMONIC, "")?;
    identity.save_with_options(&path, IdentitySaveOptions::default())?;

    let mut raw: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    raw["future_field"] = serde_json::json!({"kept": true});
    std::fs::write(&path, serde_json::to_vec_pretty(&raw)?)?;

    let mut loaded = Identity::load(&path)?;
    loaded.linked_vault = Some("https://vault.example".to_string());
    loaded.save()?;

    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    assert_eq!(saved["future_field"]["kept"].as_bool(), Some(true));
    assert_eq!(
        saved["linked_vault"].as_str(),
        Some("https://vault.example")
    );
    assert!(saved["mnemonic_stored"].is_null());

    Ok(())
}

#[test]
fn identity_load_or_mint_creates_identity_once() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("identity.json");

    let first = Identity::load_or_mint(&path)?;
    let second = Identity::load_or_mint(&path)?;

    assert!(path.is_file());
    assert_eq!(first.did, second.did);
    assert!(first.mnemonic().is_some());
    assert_eq!(second.mnemonic(), None);

    Ok(())
}
