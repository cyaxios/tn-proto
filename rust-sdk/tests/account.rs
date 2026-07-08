#[cfg(feature = "http")]
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
};

#[cfg(feature = "http")]
use sha2::Digest;
use tn_proto::{Tn, TnProjectOptions};

#[test]
fn account_state_defaults_to_unbound() -> tn_proto::Result<()> {
    let tn = Tn::ephemeral()?;

    let state = tn.account().state();

    assert_eq!(state.account_id, None);
    assert!(!state.account_bound);

    Ok(())
}

#[test]
fn account_status_reports_local_binding_and_cached_key() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "account-status-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    tn.vault().set_link_state(
        tn_proto::VaultLinkState::Linked,
        tn_proto::SetLinkStateOptions {
            linked_vault: Some("https://vault.example".to_string()),
            linked_project_id: Some("proj_123".to_string()),
        },
    )?;
    let sync_dir = tn.yaml_path().parent().unwrap().join(".tn").join("sync");
    std::fs::create_dir_all(&sync_dir)?;
    std::fs::write(
        sync_dir.join("state.json"),
        r#"{"account_id":"acct_123","account_bound":true}"#,
    )?;
    let store = tn_proto::FileCredentialStore::new(temp.path().join("credentials.json"));
    let awk = tn_proto::VaultAwk::from_slice(&[3_u8; 32])?;
    store.set_account_awk("acct_123", &awk)?;

    let status = tn.account().status_with_store(&store);

    assert_eq!(status.device_did, tn.did());
    assert_eq!(status.account_id.as_deref(), Some("acct_123"));
    assert!(status.account_bound);
    assert!(status.key_cached);
    assert_eq!(status.verdict, tn_proto::AccountVerdict::BackedUp);
    assert_eq!(status.verdict.message(), "Backed up and ready.");
    assert_eq!(
        status.vault.linked_vault.as_deref(),
        Some("https://vault.example")
    );
    assert_eq!(status.vault.linked_project_id.as_deref(), Some("proj_123"));

    Ok(())
}

#[test]
fn account_logout_clears_local_binding_and_cached_key() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "account-logout-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let sync_dir = tn.yaml_path().parent().unwrap().join(".tn").join("sync");
    std::fs::create_dir_all(&sync_dir)?;
    std::fs::write(
        sync_dir.join("state.json"),
        r#"{"account_id":"acct_123","account_bound":true,"pending_claim":{"claim_url":"secret"},"other":"kept"}"#,
    )?;
    let store = tn_proto::FileCredentialStore::new(temp.path().join("credentials.json"));
    let awk = tn_proto::VaultAwk::from_slice(&[4_u8; 32])?;
    store.set_account_awk("acct_123", &awk)?;

    let result = tn.account().logout_with_store(&store)?;

    assert_eq!(result.previous_account_id.as_deref(), Some("acct_123"));
    assert!(result.deleted_cached_key);
    assert_eq!(result.status.verdict, tn_proto::AccountVerdict::NotLoggedIn);
    assert!(!result.status.account_bound);
    assert!(!result.status.key_cached);
    assert!(store.get_account_awk("acct_123")?.is_none());

    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(sync_dir.join("state.json"))?)?;
    assert!(state.get("account_id").is_none());
    assert_eq!(state["account_bound"].as_bool(), Some(false));
    assert!(state.get("pending_claim").is_none());
    assert_eq!(state["other"].as_str(), Some("kept"));

    Ok(())
}

#[test]
fn account_use_vault_updates_identity_metadata_and_preserves_unknown_fields() -> tn_proto::Result<()>
{
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "account-use-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let identity_path = temp.path().join("identity.json");
    write_identity_json(&identity_path, &[5_u8; 32])?;
    let mut doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&identity_path)?)?;
    doc["linked_vault"] = serde_json::Value::String("https://old-vault.example".to_string());
    doc["linked_account_id"] = serde_json::Value::String("acct_old".to_string());
    doc["prefs"] = serde_json::json!({"default_new_ceremony_mode":"linked"});
    std::fs::write(&identity_path, serde_json::to_vec_pretty(&doc)?)?;

    let result = tn
        .account()
        .use_vault_at(&identity_path, "https://new-vault.example/")?;

    assert_eq!(
        result.previous_linked_vault.as_deref(),
        Some("https://old-vault.example")
    );
    assert_eq!(
        result.previous_linked_account_id.as_deref(),
        Some("acct_old")
    );
    assert_eq!(
        result.metadata.linked_vault.as_deref(),
        Some("https://new-vault.example")
    );
    assert_eq!(result.metadata.linked_account_id, None);

    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&identity_path)?)?;
    assert_eq!(
        saved["linked_vault"].as_str(),
        Some("https://new-vault.example")
    );
    assert!(saved["linked_account_id"].is_null());
    assert_eq!(
        saved["prefs"]["default_new_ceremony_mode"].as_str(),
        Some("linked")
    );

    Ok(())
}

#[test]
fn account_use_vault_keeps_account_id_for_same_vault() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "account-use-same-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let identity_path = temp.path().join("identity.json");
    write_identity_json(&identity_path, &[6_u8; 32])?;
    let mut doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&identity_path)?)?;
    doc["linked_vault"] = serde_json::Value::String("https://vault.example".to_string());
    doc["linked_account_id"] = serde_json::Value::String("acct_123".to_string());
    std::fs::write(&identity_path, serde_json::to_vec_pretty(&doc)?)?;

    let result = tn
        .account()
        .use_vault_at(&identity_path, "https://vault.example/")?;

    assert_eq!(
        result.metadata.linked_vault.as_deref(),
        Some("https://vault.example")
    );
    assert_eq!(
        result.metadata.linked_account_id.as_deref(),
        Some("acct_123")
    );

    Ok(())
}

#[test]
fn account_identity_metadata_handles_missing_and_rejects_invalid_json() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "account-metadata-edge-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let missing_path = temp.path().join("missing-identity.json");

    assert_eq!(tn.account().identity_metadata_at(&missing_path)?, None);
    let err = tn
        .account()
        .use_vault_at(&missing_path, "https://vault.example")
        .unwrap_err();
    assert!(err.to_string().contains("identity.json not found"));

    let bad_path = temp.path().join("bad-identity.json");
    std::fs::write(&bad_path, "not json")?;
    let err = tn.account().identity_metadata_at(&bad_path).unwrap_err();
    assert!(err.to_string().contains("expected"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn account_connect_code_posts_signed_redeem_and_marks_bound() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![json_response(
        200,
        r#"{"account_id":"acct_123","project_id":"proj_123","project_name":"Payments"}"#,
    )])?;
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "account-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let sync_dir = tn.yaml_path().parent().unwrap().join(".tn").join("sync");
    std::fs::create_dir_all(&sync_dir)?;
    std::fs::write(
        sync_dir.join("state.json"),
        r#"{"pending_claim":{"vault_id":"old","claim_url":"secret"},"other":"kept"}"#,
    )?;

    let mut options = tn_proto::AccountConnectOptions::new(server.base_url());
    options.machine_identity_path = Some(temp.path().join("missing-machine-identity.json"));
    let result = tn.account().connect_code_http("tn_connect_test", options)?;

    assert_eq!(result.account_id, "acct_123");
    assert_eq!(result.did, tn.did());
    assert_eq!(result.signing_tier, tn_proto::SigningIdentityTier::Ceremony);
    assert_eq!(
        result.signing_source_path,
        tn.yaml_path()
            .parent()
            .unwrap()
            .join("keys")
            .join("local.private")
    );
    assert_eq!(result.project_id.as_deref(), Some("proj_123"));
    assert_eq!(result.project_name.as_deref(), Some("Payments"));

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert!(request.starts_with("POST /api/v1/account/connect-codes/redeem "));
    assert!(request
        .to_ascii_lowercase()
        .contains("content-type: application/json"));
    let body = extract_json_value(request).expect("request JSON body");
    assert_eq!(body["code"].as_str(), Some("tn_connect_test"));
    assert_eq!(body["did"].as_str(), Some(tn.did()));
    let signature = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        body["signature_b64"]
            .as_str()
            .expect("signature_b64 should be present"),
    )
    .expect("signature should be standard base64");
    let digest = sha2::Sha256::digest(b"tn_connect_test");
    assert!(tn_core::DeviceKey::verify_did(
        tn.did(),
        &digest,
        &signature
    )?);

    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(sync_dir.join("state.json"))?)?;
    assert_eq!(state["account_id"].as_str(), Some("acct_123"));
    assert_eq!(state["account_bound"].as_bool(), Some(true));
    assert!(state.get("pending_claim").is_none());
    assert_eq!(state["other"].as_str(), Some("kept"));

    assert_eq!(tn.account().account_id().as_deref(), Some("acct_123"));
    assert!(tn.account().is_bound());

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn account_connect_code_uses_supplied_identity_before_machine_or_ceremony() -> tn_proto::Result<()>
{
    let server = LocalHttpServer::start(vec![json_response(200, r#"{"account_id":"acct_sup"}"#)])?;
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "account-supplied-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let supplied_seed = [9_u8; 32];
    let supplied_path = temp.path().join("supplied-identity.json");
    write_identity_json(&supplied_path, &supplied_seed)?;
    let supplied = tn_core::DeviceKey::from_private_bytes(&supplied_seed)?;

    let mut options = tn_proto::AccountConnectOptions::new(server.base_url());
    options.supplied_identity_path = Some(supplied_path.clone());
    let result = tn.account().connect_code_http("tn_connect_sup", options)?;

    assert_eq!(result.did, supplied.did());
    assert_eq!(result.signing_tier, tn_proto::SigningIdentityTier::Supplied);
    assert_eq!(result.signing_source_path, supplied_path);
    let request = server.requests().remove(0);
    let body = extract_json_value(&request).expect("request JSON body");
    assert_eq!(body["did"].as_str(), Some(supplied.did()));
    let metadata = tn
        .account()
        .identity_metadata_at(&supplied_path)?
        .expect("supplied identity metadata");
    assert_eq!(metadata.linked_account_id.as_deref(), Some("acct_sup"));
    assert_eq!(
        metadata.linked_vault.as_deref(),
        Some(server.base_url().as_str())
    );

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn account_connect_code_uses_machine_identity_before_ceremony() -> tn_proto::Result<()> {
    let server =
        LocalHttpServer::start(vec![json_response(200, r#"{"account_id":"acct_machine"}"#)])?;
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "account-machine-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let machine_seed = [7_u8; 32];
    let machine_path = temp.path().join("machine-identity.json");
    write_identity_json(&machine_path, &machine_seed)?;
    let machine = tn_core::DeviceKey::from_private_bytes(&machine_seed)?;

    let mut options = tn_proto::AccountConnectOptions::new(server.base_url());
    options.machine_identity_path = Some(machine_path.clone());
    let result = tn
        .account()
        .connect_code_http("tn_connect_machine", options)?;

    assert_eq!(result.did, machine.did());
    assert_eq!(result.signing_tier, tn_proto::SigningIdentityTier::Machine);
    assert_eq!(result.signing_source_path, machine_path);

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn account_connect_code_skips_corrupt_machine_identity_to_ceremony() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![json_response(
        200,
        r#"{"account_id":"acct_fallback"}"#,
    )])?;
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "account-fallback-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let machine_path = temp.path().join("corrupt-identity.json");
    std::fs::write(&machine_path, r#"{"device_priv_b64_enc":"not base64!"}"#)?;

    let mut options = tn_proto::AccountConnectOptions::new(server.base_url());
    options.machine_identity_path = Some(machine_path);
    let result = tn
        .account()
        .connect_code_http("tn_connect_fallback", options)?;

    assert_eq!(result.did, tn.did());
    assert_eq!(result.signing_tier, tn_proto::SigningIdentityTier::Ceremony);

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn account_connect_code_errors_on_bad_supplied_identity() -> tn_proto::Result<()> {
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "account-bad-supplied-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;
    let supplied_path = temp.path().join("bad-identity.json");
    std::fs::write(&supplied_path, r#"{"device_priv_b64_enc":"not base64!"}"#)?;

    let mut options = tn_proto::AccountConnectOptions::new("http://127.0.0.1:9");
    options.supplied_identity_path = Some(supplied_path);
    let err = tn
        .account()
        .connect_code_http("tn_connect_bad_supplied", options)
        .unwrap_err();

    assert!(err.to_string().contains("--identity"));

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn account_connect_code_rejects_server_error_without_marking_bound() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![json_response(410, r#"{"error":"expired"}"#)])?;
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "account-error-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    let err = tn
        .account()
        .connect_code_http(
            "tn_connect_expired",
            tn_proto::AccountConnectOptions::new(server.base_url()),
        )
        .unwrap_err();

    assert!(err.to_string().contains("returned 410"));
    assert!(!tn.account().is_bound());

    Ok(())
}

#[cfg(feature = "http")]
#[test]
fn account_connect_code_rejects_malformed_success_response() -> tn_proto::Result<()> {
    let server = LocalHttpServer::start(vec![json_response(200, r#"{"project_id":"proj"}"#)])?;
    let temp = tempfile::tempdir()?;
    let tn = Tn::init_project_with_options(
        "account-malformed-demo",
        TnProjectOptions {
            project_dir: Some(temp.path().to_path_buf()),
            ..Default::default()
        },
    )?;

    let err = tn
        .account()
        .connect_code_http(
            "tn_connect_bad",
            tn_proto::AccountConnectOptions::new(server.base_url()),
        )
        .unwrap_err();

    assert!(err.to_string().contains("account_id"));
    assert!(!tn.account().is_bound());

    Ok(())
}

#[cfg(feature = "http")]
struct LocalHttpServer {
    base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
    handle: Option<thread::JoinHandle<()>>,
}

#[cfg(feature = "http")]
impl LocalHttpServer {
    fn start(responses: Vec<String>) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let base_url = format!("http://{}", listener.local_addr()?);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let thread_requests = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            for response in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let request = read_http_request(&mut stream);
                thread_requests.lock().unwrap().push(request);
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        Ok(Self {
            base_url,
            requests,
            handle: Some(handle),
        })
    }

    fn base_url(&self) -> String {
        self.base_url.clone()
    }

    fn requests(&self) -> Vec<String> {
        std::thread::sleep(std::time::Duration::from_millis(25));
        self.requests.lock().unwrap().clone()
    }
}

#[cfg(feature = "http")]
impl Drop for LocalHttpServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(feature = "http")]
fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
    let mut data = Vec::new();
    let mut buffer = [0_u8; 4096];

    loop {
        let n = stream.read(&mut buffer).unwrap_or(0);
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..n]);
        if http_request_complete(&data) {
            break;
        }
    }

    String::from_utf8_lossy(&data).to_string()
}

#[cfg(feature = "http")]
fn http_request_complete(data: &[u8]) -> bool {
    let Some(header_end) = data.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&data[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    data.len() >= header_end + 4 + content_length
}

#[cfg(feature = "http")]
fn json_response(status: u16, body: &str) -> String {
    let reason = match status {
        200 => "OK",
        410 => "Gone",
        _ => "Status",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(feature = "http")]
fn extract_json_value(request: &str) -> Option<serde_json::Value> {
    let (_, body) = request.split_once("\r\n\r\n")?;
    serde_json::from_str::<serde_json::Value>(body).ok()
}

fn write_identity_json(path: &std::path::Path, seed: &[u8; 32]) -> tn_proto::Result<()> {
    let device = tn_core::DeviceKey::from_private_bytes(seed)?;
    let doc = serde_json::json!({
        "did": device.did(),
        "device_pub_b64": base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            device.public_bytes()
        ),
        "device_priv_b64_enc": base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            seed
        ),
        "device_priv_enc_method": "none",
        "version": 1
    });
    std::fs::write(path, serde_json::to_vec_pretty(&doc)?)?;
    Ok(())
}
