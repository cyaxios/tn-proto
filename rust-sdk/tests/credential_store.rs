use base64::Engine as _;
use std::sync::{Mutex, OnceLock};
use tn_proto::{
    awk_key_name, default_credential_store, default_identity_dir, default_identity_path,
    load_cached_account_awk, FileCredentialStore, VaultAwk,
};

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[test]
fn file_credential_store_sets_gets_and_deletes_values() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let store = FileCredentialStore::new(temp.path().join("credentials.json"));

    assert_eq!(awk_key_name("acct_123"), "awk:acct_123");
    assert_eq!(store.get("missing")?, None);

    store.set("token", b"secret bytes")?;
    assert_eq!(store.get("token")?.as_deref(), Some(&b"secret bytes"[..]));

    store.delete("token")?;
    store.delete("token")?;
    assert_eq!(store.get("token")?, None);

    Ok(())
}

#[test]
fn file_credential_store_caches_account_awk() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let store = FileCredentialStore::new(temp.path().join("credentials.json"));
    let awk = VaultAwk::new([7_u8; 32]);

    store.set_account_awk("acct_abc", &awk)?;
    let loaded = store
        .get_account_awk("acct_abc")?
        .expect("cached AWK should load");

    assert_eq!(loaded.as_bytes(), awk.as_bytes());

    store.delete_account_awk("acct_abc")?;
    assert!(store.get_account_awk("acct_abc")?.is_none());

    Ok(())
}

#[test]
fn default_credential_store_uses_identity_dir_override() -> tn_proto::Result<()> {
    let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let temp = tempfile::tempdir()?;
    let old_identity_dir = std::env::var_os("TN_IDENTITY_DIR");
    let old_xdg_data_home = std::env::var_os("XDG_DATA_HOME");
    let restore = EnvRestore {
        identity_dir: old_identity_dir,
        xdg_data_home: old_xdg_data_home,
    };

    std::env::set_var("TN_IDENTITY_DIR", temp.path());
    std::env::remove_var("XDG_DATA_HOME");

    assert_eq!(default_identity_dir(), temp.path());
    assert_eq!(default_identity_path(), temp.path().join("identity.json"));
    assert_eq!(
        default_credential_store().path(),
        temp.path().join("credentials.json").as_path()
    );

    drop(restore);
    Ok(())
}

#[test]
fn default_identity_dir_uses_xdg_data_home_when_set() -> tn_proto::Result<()> {
    let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let temp = tempfile::tempdir()?;
    let old_identity_dir = std::env::var_os("TN_IDENTITY_DIR");
    let old_xdg_data_home = std::env::var_os("XDG_DATA_HOME");
    let restore = EnvRestore {
        identity_dir: old_identity_dir,
        xdg_data_home: old_xdg_data_home,
    };

    std::env::remove_var("TN_IDENTITY_DIR");
    std::env::set_var("XDG_DATA_HOME", temp.path());

    assert_eq!(default_identity_dir(), temp.path().join("tn"));
    assert_eq!(
        default_credential_store().path(),
        temp.path().join("tn").join("credentials.json").as_path()
    );

    drop(restore);
    Ok(())
}

#[test]
fn load_cached_account_awk_is_best_effort() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("credentials.json");
    let store = FileCredentialStore::new(&path);

    assert!(load_cached_account_awk(&store, "acct_missing").is_none());

    std::fs::write(
        &path,
        serde_json::json!({
            "awk:bad-base64": "not base64!",
            "awk:short": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                [1_u8; 31]
            )
        })
        .to_string(),
    )?;

    assert!(load_cached_account_awk(&store, "bad-base64").is_none());
    assert!(load_cached_account_awk(&store, "short").is_none());

    let awk = VaultAwk::new([9_u8; 32]);
    store.set_account_awk("acct_ok", &awk)?;

    assert_eq!(
        load_cached_account_awk(&store, "acct_ok")
            .expect("valid cached AWK")
            .as_bytes(),
        awk.as_bytes()
    );

    Ok(())
}

struct EnvRestore {
    identity_dir: Option<std::ffi::OsString>,
    xdg_data_home: Option<std::ffi::OsString>,
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        restore_env("TN_IDENTITY_DIR", self.identity_dir.take());
        restore_env("XDG_DATA_HOME", self.xdg_data_home.take());
    }
}

fn restore_env(name: &str, value: Option<std::ffi::OsString>) {
    match value {
        Some(value) => std::env::set_var(name, value),
        None => std::env::remove_var(name),
    }
}

#[test]
fn file_credential_store_treats_corrupt_or_invalid_values_as_empty() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("credentials.json");
    let store = FileCredentialStore::new(&path);

    std::fs::write(&path, b"not json")?;
    assert_eq!(store.get("anything")?, None);

    std::fs::write(
        &path,
        serde_json::json!({
            "bad": "not base64!",
            "awk:short": base64::engine::general_purpose::STANDARD.encode([1_u8; 31])
        })
        .to_string(),
    )?;
    assert_eq!(store.get("bad")?, None);
    let err = store.get_account_awk("short").unwrap_err();
    assert!(err.to_string().contains("32 bytes"));

    Ok(())
}
