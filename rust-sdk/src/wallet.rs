//! Headless wallet sync orchestration helpers.
//!
//! This namespace will compose account inbox pull, package absorb, group-key
//! publish, and encrypted body push. The first chunk establishes local
//! path/state conventions shared with Python and TypeScript.

use std::fs;
use std::path::{Path, PathBuf};

#[cfg(feature = "http")]
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::pkg::{AbsorbReceiptExt, AbsorbStatus};
use crate::tn::Tn;
#[cfg(feature = "http")]
use crate::vault::{VaultHttpProjectClient, VaultInboxSnapshot, VaultLinkState};
#[cfg(feature = "http")]
use crate::vault::{
    VaultPushWithAwkResult, VaultPushWithCachedAwkOptions, VaultPushWithPassphraseOptions,
};
#[cfg(feature = "http")]
use crate::CredentialStore;
#[cfg(feature = "http")]
use crate::Error;
use crate::Result;

/// Runtime wallet namespace for a [`Tn`] handle.
pub struct Wallet<'a> {
    tn: &'a Tn,
}

/// Options for a full wallet sync.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct WalletSyncOptions {
    /// Stage inbox packages without absorbing or pushing.
    pub pull_only: bool,
    /// Skip pull/absorb and only push the encrypted project body.
    pub push_only: bool,
    /// Retry the push side without first pulling.
    pub drain_queue: bool,
    /// Optional vault URL override.
    pub vault: Option<String>,
    /// Optional `identity.json` path override.
    pub identity_path: Option<PathBuf>,
    /// Optional account id override for cached AWK lookup.
    pub account_id: Option<String>,
    /// Optional passphrase fallback used when no cached account AWK exists.
    pub passphrase: Option<String>,
    /// Optional credential id used when deriving an account AWK from
    /// `passphrase`.
    pub credential_id: Option<String>,
    /// Optional vault project id override for the encrypted body push.
    pub project_id: Option<String>,
    /// Optional group subset for the group-key publish leg.
    pub group_key_groups: Option<Vec<String>>,
}

impl std::fmt::Debug for WalletSyncOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletSyncOptions")
            .field("pull_only", &self.pull_only)
            .field("push_only", &self.push_only)
            .field("drain_queue", &self.drain_queue)
            .field("vault", &self.vault)
            .field("identity_path", &self.identity_path)
            .field("account_id", &self.account_id)
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "<redacted>"),
            )
            .field("credential_id", &self.credential_id)
            .field("project_id", &self.project_id)
            .field("group_key_groups", &self.group_key_groups)
            .finish()
    }
}

/// Summary from a full wallet sync.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WalletSyncResult {
    /// Number of inbox packages staged locally.
    pub staged: usize,
    /// Number of packages skipped during staging.
    pub skipped: usize,
    /// Number of packages absorbed.
    pub absorbed: usize,
    /// Number of valid staged packages that produced no local changes.
    pub no_op: usize,
    /// Number of packages parsed but left for later state.
    pub stashed: usize,
    /// Number of staged packages rejected during absorb.
    pub rejected: usize,
    /// Whether the encrypted project body was pushed.
    pub pushed: bool,
    /// Group names whose key snapshots were published.
    pub published_groups: Vec<String>,
    /// Vault account id from local sync state after sync completes, when
    /// present.
    pub account_id: Option<String>,
    /// True when local sync state says this ceremony is account-bound.
    pub account_bound: bool,
    /// Non-fatal warnings observed during sync.
    pub warnings: Vec<String>,
}

/// Options for staging account inbox packages.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WalletStageInboxOptions {
    /// Optional vault URL override.
    pub vault: Option<String>,
    /// Optional `identity.json` path override.
    pub identity_path: Option<PathBuf>,
}

/// Summary from staging account inbox packages.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WalletStageInboxResult {
    /// Paths of newly staged `.tnpkg` files.
    pub staged_paths: Vec<PathBuf>,
    /// Number of inbox entries skipped.
    pub skipped: usize,
    /// True when staging was skipped because local state is not account-bound.
    pub not_bound: bool,
    /// True when the vault did not authorize the account inbox pull.
    pub unauthorized: bool,
}

/// Summary from pulling and absorbing account inbox packages.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WalletPullAbsorbResult {
    /// Staging summary.
    pub staged: WalletStageInboxResult,
    /// Number of packages absorbed.
    pub absorbed: usize,
    /// Number of valid packages that produced no local changes.
    pub no_op: usize,
    /// Number of packages parsed but left for a later runtime/state.
    pub stashed: usize,
    /// Number of packages rejected.
    pub rejected: usize,
    /// Non-fatal warnings observed during absorb.
    pub warnings: Vec<String>,
}

/// Options for publishing group-key snapshots to the account inbox.
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WalletPublishGroupKeysOptions {
    /// Optional group subset. The default publishes all eligible BTN groups.
    pub groups: Option<Vec<String>>,
    /// Optional inbox timestamp override for tests or externally coordinated
    /// sync. The vault expects `YYYYMMDDTHHMMSSffffffZ`.
    pub ts: Option<String>,
}

/// Summary from publishing a group-key snapshot.
#[cfg(feature = "http")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WalletPublishGroupKeysResult {
    /// Groups included in the published snapshot.
    pub published_groups: Vec<String>,
    /// Vault response for the stored snapshot. `None` means there was no
    /// publishable group material.
    pub snapshot: Option<VaultInboxSnapshot>,
}

/// Local wallet paths derived from a ceremony `tn.yaml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPaths {
    /// Root sidecar directory for this yaml stem.
    pub stem_dir: PathBuf,
    /// Inbox directory for staged account packages.
    pub inbox_dir: PathBuf,
    /// Sync-state sidecar JSON path.
    pub sync_state_path: PathBuf,
}

impl<'a> Wallet<'a> {
    pub(crate) fn new(tn: &'a Tn) -> Self {
        Self { tn }
    }

    /// Return wallet sidecar paths for the active ceremony.
    pub fn paths(&self) -> WalletPaths {
        wallet_paths(self.tn.yaml_path())
    }

    /// True iff `.tn/<stem>/sync/state.json` has `account_bound: true`.
    pub fn is_account_bound(&self) -> bool {
        is_account_bound(self.tn.yaml_path())
    }

    /// Return the inbox root for staged account packages.
    pub fn inbox_dir(&self) -> PathBuf {
        inbox_dir(self.tn.yaml_path())
    }

    /// Absorb already-staged `.tnpkg` files from the local wallet inbox.
    ///
    /// One bad package does not abort the whole pass. Rejected packages and
    /// local absorb errors are counted and left in place so callers can inspect
    /// or retry them.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the inbox directory cannot be traversed.
    pub fn absorb_staged_packages(&self) -> Result<WalletPullAbsorbResult> {
        let mut result = WalletPullAbsorbResult::default();
        for path in staged_package_paths(&self.inbox_dir())? {
            match self.tn.pkg().absorb_path(&path) {
                Ok(receipt) => match receipt.status() {
                    AbsorbStatus::Accepted => result.absorbed += 1,
                    AbsorbStatus::NoOp => result.no_op += 1,
                    AbsorbStatus::Stashed => result.stashed += 1,
                    AbsorbStatus::Rejected => {
                        result.rejected += 1;
                        result
                            .warnings
                            .push(format!("rejected staged package {}", path.display()));
                    }
                },
                Err(error) => {
                    result.rejected += 1;
                    result.warnings.push(format!(
                        "failed to absorb staged package {}: {error}",
                        path.display()
                    ));
                }
            }
        }
        Ok(result)
    }

    /// Stage authenticated account inbox packages into the local wallet inbox.
    ///
    /// This is the first pull leg of wallet sync. It lists vault account inbox
    /// metadata, downloads available `.tnpkg` packages, and writes them under
    /// `<inbox>/<safe_from_did>/<safe_ceremony_id>/<safe_ts>.tnpkg`.
    ///
    /// `401` and `403` responses are returned as non-fatal
    /// [`WalletStageInboxResult::unauthorized`] so unattended sync can
    /// continue with push-only work.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the vault list response is malformed, a
    /// non-stale download fails, or local filesystem writes fail.
    #[cfg(feature = "http")]
    pub fn stage_account_inbox(
        &self,
        client: &VaultHttpProjectClient,
        _options: WalletStageInboxOptions,
    ) -> Result<WalletStageInboxResult> {
        if !self.can_stage_account_inbox() {
            return Ok(WalletStageInboxResult {
                not_bound: true,
                ..Default::default()
            });
        }

        let items = match client.list_account_inbox() {
            Ok(items) => items,
            Err(Error::VaultHttp(message))
                if message.contains("returned 401") || message.contains("returned 403") =>
            {
                return Ok(WalletStageInboxResult {
                    unauthorized: true,
                    ..Default::default()
                });
            }
            Err(error) => return Err(error),
        };

        let mut result = WalletStageInboxResult::default();
        for item in items {
            if item.consumed_at.is_some() {
                result.skipped += 1;
                continue;
            }

            let Some(from_did) = safe_path_segment(&item.publisher_identity) else {
                result.skipped += 1;
                continue;
            };
            let Some(ceremony_id) = safe_path_segment(&item.ceremony_id) else {
                result.skipped += 1;
                continue;
            };
            let Some(ts) = safe_path_segment(&item.ts) else {
                result.skipped += 1;
                continue;
            };
            let dest = self
                .inbox_dir()
                .join(from_did)
                .join(ceremony_id)
                .join(format!("{ts}.tnpkg"));

            if dest.exists() {
                result.skipped += 1;
                continue;
            }

            match client.download_account_inbox_package(
                &item.publisher_identity,
                &item.ceremony_id,
                &item.ts,
            )? {
                Some(bytes) => {
                    if let Some(parent) = dest.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    tn_core::keystore_backend::atomic_write_bytes(&dest, &bytes)?;
                    result.staged_paths.push(dest);
                }
                None => {
                    result.skipped += 1;
                }
            }
        }
        Ok(result)
    }

    /// Stage account inbox packages from the vault, then absorb all staged
    /// local `.tnpkg` files.
    ///
    /// This composes the first two legs of wallet sync:
    /// `pull account inbox -> absorb staged packages`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] for fatal staging errors or inbox traversal
    /// failures. Individual bad packages are reported on the returned result.
    #[cfg(feature = "http")]
    pub fn pull_and_absorb(
        &self,
        client: &VaultHttpProjectClient,
        options: WalletStageInboxOptions,
    ) -> Result<WalletPullAbsorbResult> {
        let staged = self.stage_account_inbox(client, options)?;
        let mut result = self.absorb_staged_packages()?;
        result.staged = staged;
        Ok(result)
    }

    /// Push the local ceremony body using a passphrase-derived account AWK.
    ///
    /// This is the wallet-level wrapper around
    /// [`crate::Vault::push_body_with_passphrase_http_client`]. It fetches the
    /// account credential wrap, derives the AWK from `passphrase`, reuses or
    /// creates the project BEK wrap, and uploads the encrypted whole-body blob.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when credential fetch or AWK derivation fails,
    /// linked project resolution fails, or the encrypted body upload fails.
    #[cfg(feature = "http")]
    pub fn push_body(
        &self,
        client: &VaultHttpProjectClient,
        passphrase: &str,
        options: VaultPushWithPassphraseOptions,
    ) -> Result<VaultPushWithAwkResult> {
        self.tn
            .vault()
            .push_body_with_passphrase_http_client(client, passphrase, options)
    }

    /// Push the local ceremony body using a cached account AWK.
    ///
    /// This is the unattended wallet-sync path. It prefers a cached AWK in
    /// `store`; when the cache misses and `options.passphrase` is supplied,
    /// the lower-level vault helper derives and stores the AWK before pushing.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when no cached AWK or passphrase fallback is
    /// available, linked project resolution fails, or the encrypted body upload
    /// fails.
    #[cfg(feature = "http")]
    pub fn push_body_with_cached_awk<S: CredentialStore + ?Sized>(
        &self,
        client: &VaultHttpProjectClient,
        store: &S,
        options: VaultPushWithCachedAwkOptions,
    ) -> Result<VaultPushWithAwkResult> {
        self.tn
            .vault()
            .push_body_with_cached_awk_http_client(client, store, options)
    }

    /// Publish local group-key material to this device's account inbox.
    ///
    /// This exports the Python/TypeScript-compatible group-key snapshot
    /// (`kind = full_keystore`, `scope = group_keys`) and posts it to
    /// `/api/v1/inbox/{did}/snapshots/{ceremony}/{ts}.tnpkg`.
    ///
    /// A ceremony with no matching BTN group key material is treated as
    /// "nothing to publish" and returns an empty result.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when package export fails for reasons other
    /// than no matching group material, or the vault rejects the snapshot.
    #[cfg(feature = "http")]
    pub fn publish_group_keys(
        &self,
        client: &VaultHttpProjectClient,
        options: WalletPublishGroupKeysOptions,
    ) -> Result<WalletPublishGroupKeysResult> {
        let path = group_keys_temp_path();
        let export = self.tn.pkg().export_group_keys(&path, options.groups);
        let path = match export {
            Ok(path) => path,
            Err(error) if error.to_string().contains("group_keys: no btn groups") => {
                return Ok(WalletPublishGroupKeysResult::default());
            }
            Err(error) => return Err(error),
        };

        let info = self.tn.pkg().inspect_path(&path)?;
        let published_groups = group_key_manifest_groups(&info.manifest.state);
        let ts = options.ts.unwrap_or_else(inbox_snapshot_timestamp);
        let bytes = fs::read(&path)?;
        let snapshot = client.post_inbox_snapshot(
            &info.manifest.publisher_identity,
            &info.manifest.ceremony_id,
            &ts,
            bytes,
        )?;
        let _ = fs::remove_file(&path);

        Ok(WalletPublishGroupKeysResult {
            published_groups,
            snapshot: Some(snapshot),
        })
    }

    /// Run the headless wallet sync flow with a cached account AWK.
    ///
    /// Default behavior is:
    ///
    /// 1. pull account inbox packages;
    /// 2. absorb all staged packages;
    /// 3. push the encrypted ceremony body.
    ///
    /// `pull_only` stops after staging. `push_only` and `drain_queue` skip the
    /// pull/absorb leg and only push the encrypted body.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when a fatal pull error occurs, the inbox
    /// cannot be traversed, `account_id` is missing for a push leg, or the
    /// encrypted body push fails.
    #[cfg(feature = "http")]
    pub fn sync_with_cached_awk<S: CredentialStore + ?Sized>(
        &self,
        client: &VaultHttpProjectClient,
        store: &S,
        options: WalletSyncOptions,
    ) -> Result<WalletSyncResult> {
        let mut result = WalletSyncResult::default();
        apply_account_state(&mut result, wallet_account_state(self.tn.yaml_path()));

        if options.pull_only {
            let staged = self.stage_account_inbox(
                client,
                WalletStageInboxOptions {
                    vault: options.vault,
                    identity_path: options.identity_path,
                },
            )?;
            apply_staging_summary(&mut result, &staged);
            apply_account_state(&mut result, wallet_account_state(self.tn.yaml_path()));
            persist_wallet_sync_result(self.tn.yaml_path(), &result)?;
            return Ok(result);
        }

        if !options.push_only && !options.drain_queue {
            let pull = self.pull_and_absorb(
                client,
                WalletStageInboxOptions {
                    vault: options.vault.clone(),
                    identity_path: options.identity_path.clone(),
                },
            )?;
            apply_pull_absorb_summary(&mut result, pull);

            let published = self.publish_group_keys(
                client,
                WalletPublishGroupKeysOptions {
                    groups: options.group_key_groups.clone(),
                    ts: None,
                },
            )?;
            result.published_groups = published.published_groups;
        }

        let account_id = options
            .account_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Error::InvalidArgument("wallet sync requires account_id".into()))?
            .to_string();
        let mut push_options = VaultPushWithCachedAwkOptions::new(account_id);
        push_options.project_id = options.project_id;
        push_options.passphrase = options.passphrase;
        push_options.credential_id = options.credential_id;
        self.push_body_with_cached_awk(client, store, push_options)?;
        result.pushed = true;
        apply_account_state(&mut result, wallet_account_state(self.tn.yaml_path()));
        persist_wallet_sync_result(self.tn.yaml_path(), &result)?;

        Ok(result)
    }

    #[cfg(feature = "http")]
    fn can_stage_account_inbox(&self) -> bool {
        if self.is_account_bound() {
            return true;
        }
        self.tn
            .vault()
            .link_state()
            .map(|state| {
                state.state == VaultLinkState::Linked
                    && state
                        .linked_vault
                        .as_deref()
                        .map(str::trim)
                        .is_some_and(|value| !value.is_empty())
            })
            .unwrap_or(false)
    }
}

/// Return wallet sidecar paths for `yaml_path`.
pub fn wallet_paths(yaml_path: &Path) -> WalletPaths {
    let stem_dir = stem_dir(yaml_path);
    WalletPaths {
        inbox_dir: stem_dir.join("inbox"),
        sync_state_path: stem_dir.join("sync").join("state.json"),
        stem_dir,
    }
}

/// Return the per-yaml-stem sidecar directory.
pub fn stem_dir(yaml_path: &Path) -> PathBuf {
    let parent = yaml_path.parent().unwrap_or_else(|| Path::new(""));
    let stem = yaml_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("tn");
    parent.join(".tn").join(stem)
}

/// Return the inbox directory for staged account packages.
pub fn inbox_dir(yaml_path: &Path) -> PathBuf {
    wallet_paths(yaml_path).inbox_dir
}

/// Return the sync-state sidecar path.
pub fn sync_state_path(yaml_path: &Path) -> PathBuf {
    wallet_paths(yaml_path).sync_state_path
}

/// True iff sync state has `account_bound: true`.
///
/// Missing, unreadable, malformed, or non-object state is treated as unbound.
pub fn is_account_bound(yaml_path: &Path) -> bool {
    fs::read(sync_state_path(yaml_path))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| {
            value
                .get("account_bound")
                .and_then(serde_json::Value::as_bool)
        })
        == Some(true)
}

/// Sanitize a vault-supplied path segment for inbox staging.
///
/// DIDs contain `:` and Windows path components cannot. Separators are
/// replaced with `_`, while empty/traversal-like values are rejected.
pub fn safe_path_segment(segment: &str) -> Option<String> {
    let cleaned = segment.replace([':', '/', '\\'], "_");
    if cleaned.is_empty()
        || cleaned == "."
        || cleaned == ".."
        || cleaned.starts_with("..")
        || cleaned.contains('\0')
    {
        None
    } else {
        Some(cleaned)
    }
}

fn staged_package_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    collect_staged_package_paths(root, &mut paths)?;
    paths.sort();
    Ok(paths)
}

fn collect_staged_package_paths(dir: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_staged_package_paths(&path, paths)?;
        } else if file_type.is_file()
            && path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("tnpkg"))
        {
            paths.push(path);
        }
    }
    Ok(())
}

#[cfg(feature = "http")]
fn apply_staging_summary(result: &mut WalletSyncResult, staged: &WalletStageInboxResult) {
    result.staged += staged.staged_paths.len();
    result.skipped += staged.skipped;
    if staged.not_bound {
        result
            .warnings
            .push("account inbox pull skipped because wallet is not account-bound".into());
    }
    if staged.unauthorized {
        result
            .warnings
            .push("account inbox pull skipped because vault returned unauthorized".into());
    }
}

#[cfg(feature = "http")]
fn apply_pull_absorb_summary(result: &mut WalletSyncResult, pull: WalletPullAbsorbResult) {
    apply_staging_summary(result, &pull.staged);
    result.absorbed += pull.absorbed;
    result.no_op += pull.no_op;
    result.stashed += pull.stashed;
    result.rejected += pull.rejected;
    result.warnings.extend(pull.warnings);
}

#[cfg(feature = "http")]
struct WalletAccountState {
    account_id: Option<String>,
    account_bound: bool,
}

#[cfg(feature = "http")]
fn apply_account_state(result: &mut WalletSyncResult, state: WalletAccountState) {
    result.account_id = state.account_id;
    result.account_bound = state.account_bound;
}

#[cfg(feature = "http")]
fn wallet_account_state(yaml_path: &Path) -> WalletAccountState {
    let state = load_wallet_sync_state(yaml_path);
    let account_id = state
        .get("account_id")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let account_bound = state.get("account_bound").and_then(JsonValue::as_bool) == Some(true);
    WalletAccountState {
        account_id,
        account_bound,
    }
}

#[cfg(feature = "http")]
fn persist_wallet_sync_result(yaml_path: &Path, result: &WalletSyncResult) -> Result<()> {
    let mut state = load_wallet_sync_state(yaml_path);
    state.insert(
        "last_wallet_sync_at".to_string(),
        JsonValue::String(wallet_sync_timestamp()),
    );
    state.insert(
        "last_wallet_sync".to_string(),
        serde_json::json!({
            "staged": result.staged,
            "skipped": result.skipped,
            "absorbed": result.absorbed,
            "no_op": result.no_op,
            "stashed": result.stashed,
            "rejected": result.rejected,
            "pushed": result.pushed,
            "published_groups": result.published_groups,
            "warning_count": result.warnings.len(),
            "account_bound": result.account_bound,
            "account_id": result.account_id,
        }),
    );
    save_wallet_sync_state(yaml_path, state)
}

#[cfg(feature = "http")]
fn load_wallet_sync_state(yaml_path: &Path) -> JsonMap<String, JsonValue> {
    fs::read(sync_state_path(yaml_path))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<JsonValue>(&bytes).ok())
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default()
}

#[cfg(feature = "http")]
fn save_wallet_sync_state(yaml_path: &Path, state: JsonMap<String, JsonValue>) -> Result<()> {
    let path = sync_state_path(yaml_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(&JsonValue::Object(state))?;
    tn_core::keystore_backend::atomic_write_bytes(&path, &bytes)?;
    Ok(())
}

#[cfg(feature = "http")]
fn wallet_sync_timestamp() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(feature = "http")]
fn group_keys_temp_path() -> PathBuf {
    let stamp = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    std::env::temp_dir().join(format!(
        "tn-group-keys-{}-{stamp}.tnpkg",
        std::process::id()
    ))
}

#[cfg(feature = "http")]
fn inbox_snapshot_timestamp() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}{:06}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.microsecond()
    )
}

#[cfg(feature = "http")]
fn group_key_manifest_groups(state: &Option<serde_json::Value>) -> Vec<String> {
    let mut groups = state
        .as_ref()
        .and_then(|state| state.get("groups"))
        .and_then(serde_json::Value::as_object)
        .map(|groups| groups.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    groups.sort();
    groups
}
