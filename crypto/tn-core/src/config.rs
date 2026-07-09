//! tn.yaml parsing via serde_yml.
//!
//! Mirrors the schema emitted by `tn/config.py::create_fresh`.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// Compose-style env-var substitution applied to the raw yaml *string*
/// before the yaml parser runs.
///
/// Mirrors `_substitute_env_vars` in `tn_proto/python/tn/config.py`
/// and `substituteEnvVars` in `tn_proto/ts-sdk/src/runtime/config.ts`.
/// Recognized syntax:
///
/// * `${NAME}` — required; returns `Err(Error::ConfigEnvVarMissing)` when unset.
/// * `${NAME:-default}` — falls back to `default` (which may be empty).
/// * `$${literal}` — escape; emits the literal `${literal}` after substitution.
///
/// Variable names match `[A-Za-z_][A-Za-z0-9_]*`. No recursive expansion.
///
/// # Errors
///
/// Returns `Error::ConfigEnvVarMissing` when a `${VAR}` reference has no
/// default and the env var is not set, or `Error::ConfigEnvVarMalformed`
/// when the syntax is invalid (no closing brace, bad variable name).
///
/// # Panics
///
/// The `chars().next().expect("non-empty")` on a multi-byte utf-8 lead is
/// infallible: the loop only enters that branch when `bytes[i] >= 0x80`,
/// which guarantees `&text[i..]` starts with at least one valid utf-8
/// character. The expect documents the invariant; it cannot panic.
pub fn substitute_env_vars(text: &str, source_path: &Path) -> Result<String> {
    // Hand-rolled scanner. Avoids pulling in a regex dep just for this
    // and keeps the semantics identical across all three SDKs.
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b != b'$' {
            // Append a single char (handle utf-8 by walking char-by-char
            // when a non-ASCII lead byte appears).
            if b < 0x80 {
                out.push(b as char);
                i += 1;
            } else {
                // Multi-byte utf-8 char: copy via the str slice.
                let s = &text[i..];
                let ch = s.chars().next().expect("non-empty");
                out.push(ch);
                i += ch.len_utf8();
            }
            continue;
        }

        // We're at `$`. Check for `$$` (escape) first.
        if i + 1 < bytes.len() && bytes[i + 1] == b'$' {
            // The `$$` collapses to a single `$` after substitution.
            // Consume both bytes; emit one literal `$`.
            out.push('$');
            i += 2;
            continue;
        }

        // Not an escape. Is it a `${...}` reference?
        if i + 1 >= bytes.len() || bytes[i + 1] != b'{' {
            // Lone `$`. Pass through.
            out.push('$');
            i += 1;
            continue;
        }

        // Find the closing `}`.
        let body_start = i + 2;
        let close = bytes[body_start..]
            .iter()
            .position(|&c| c == b'}')
            .map(|p| body_start + p);
        let Some(close) = close else {
            return Err(Error::ConfigEnvVarMalformed {
                token: text[i..].chars().take(32).collect(),
                path: source_path.to_path_buf(),
                line: line_of(text, i),
            });
        };

        let body = &text[body_start..close];
        let (name, default) = match body.find(":-") {
            Some(p) => (&body[..p], Some(&body[p + 2..])),
            None => (body, None),
        };

        if !is_valid_var_name(name) {
            return Err(Error::ConfigEnvVarMalformed {
                token: text[i..=close].to_string(),
                path: source_path.to_path_buf(),
                line: line_of(text, i),
            });
        }

        match std::env::var(name) {
            Ok(v) => out.push_str(&v),
            Err(_) => match default {
                Some(d) => out.push_str(d),
                None => {
                    return Err(Error::ConfigEnvVarMissing {
                        var: name.to_string(),
                        path: source_path.to_path_buf(),
                        line: line_of(text, i),
                    });
                }
            },
        }
        i = close + 1;
    }
    Ok(out)
}

fn is_valid_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn line_of(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())]
        .bytes()
        .filter(|&b| b == b'\n')
        .count()
        + 1
}

/// Top-level ceremony metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ceremony {
    /// Ceremony identifier (e.g. `cer_abc123`).
    pub id: String,
    /// Ceremony mode: `"local"` or `"linked"`.
    #[serde(default = "default_local")]
    pub mode: String,
    /// Cipher name: `"btn"`, `"jwe"`, or `"hibe"`.
    pub cipher: String,
    /// Vault URL for linked-mode ceremonies.
    #[serde(default)]
    pub linked_vault: Option<String>,
    /// Project id for linked-mode ceremonies.
    #[serde(default)]
    pub linked_project_id: Option<String>,
    /// Legacy/ignored sync logs flag. Vault sync never includes
    /// application logs.
    #[serde(default)]
    pub sync_logs: bool,
    /// Where to route `tn.*` admin events: `"main_log"` or path template.
    ///
    /// Yaml key: `admin_log_location` (preferred) or legacy
    /// `protocol_events_location`. Default is the dedicated admin log
    /// file alongside the main log, matching Python's
    /// `LoadedConfig.admin_log_location`.
    #[serde(
        default = "default_pel",
        alias = "protocol_events_location",
        rename = "admin_log_location"
    )]
    pub protocol_events_location: String,
    /// Whether each emitted entry is signed by the publisher's Ed25519
    /// device key. `true` (default) produces fully attested logs. `false`
    /// skips the signature step — entries still carry row_hash + prev_hash
    /// for chain integrity, but lack identity attestation. Useful for
    /// high-throughput observability flows where batch-signing (RFC
    /// `2026-04-22-tn-transaction-protocol`) is not yet implemented.
    #[serde(default = "default_sign")]
    pub sign: bool,
    /// Whether to maintain a per-event_type hash chain (sequence +
    /// prev_hash + cross-process tip refresh) for emitted entries.
    /// `true` (default) gives full chain integrity at the cost of a
    /// per-emit advisory file lock and tail-scan. `false` skips the
    /// lock and the tip refresh entirely — emits write
    /// `sequence: 1` and `prev_hash: ""`, no `.emit.lock` artifacts.
    ///
    /// Used by the `telemetry` and `secure_log` profiles where
    /// per-row chain integrity isn't part of the audit story and the
    /// per-emit lock cost would dominate hot paths. Set by the
    /// profile-stamping step in `python/tn/_multi.py` when minting a
    /// fresh ceremony.
    #[serde(default = "default_chain")]
    pub chain: bool,
    /// Active log-level threshold (AVL J3.2). One of "debug" / "info" /
    /// "warning" / "error", case-insensitive. ``"debug"`` (default)
    /// emits every verb; raising drops lower-priority emits before any
    /// work. Honored at init unless the caller already invoked
    /// [`crate::Runtime::set_level`] programmatically. Empty string and
    /// missing key both leave the threshold at its current value.
    #[serde(default)]
    pub log_level: String,
}

/// Project-level vault sync configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    /// Whether vault behavior is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Vault base URL.
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub url: Option<String>,
    /// Vault-side project id. Empty strings normalize to `None`.
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub linked_project_id: Option<String>,
    /// Whether the conceptual `vault.sync` handler should be active.
    #[serde(default)]
    pub autosync: bool,
    /// Sync interval in seconds.
    #[serde(default = "default_vault_sync_interval_seconds")]
    pub sync_interval_seconds: u64,
}

impl Default for Vault {
    fn default() -> Self {
        Self {
            enabled: false,
            url: None,
            linked_project_id: None,
            autosync: false,
            sync_interval_seconds: default_vault_sync_interval_seconds(),
        }
    }
}

fn default_vault_sync_interval_seconds() -> u64 {
    600
}

fn empty_string_as_none<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Option::<String>::deserialize(deserializer)?;
    Ok(v.and_then(|s| {
        let trimmed = s.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    }))
}

fn default_local() -> String {
    "local".into()
}
fn default_pel() -> String {
    // Matches Python LoadedConfig.admin_log_location default
    // (python/tn/config.py:263). Pre-2026-04-24 default was "main_log";
    // changed when admin events got their own dedicated file alongside
    // the main user log. Legacy yamls with `protocol_events_location: main_log`
    // still keep that explicit value.
    "./.tn/admin/admin.ndjson".into()
}
fn default_private() -> String {
    "private".into()
}
fn default_sign() -> bool {
    true
}
fn default_chain() -> bool {
    true
}

/// Keystore location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keystore {
    /// Path to the keystore directory (relative to yaml dir or absolute).
    pub path: String,
}

/// Main log destination.
///
/// Single path; no template substitution. For event-type-based file
/// splitting use `ceremony.protocol_events_location` (for `tn.*` events)
/// or a `handlers:` block (general). Default: `./.tn/logs/tn.ndjson` relative
/// to the yaml directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Logs {
    /// Path to the ndjson log file. Relative paths resolve against yaml dir.
    pub path: String,
}

fn default_logs() -> Logs {
    Logs {
        path: "./.tn/logs/tn.ndjson".into(),
    }
}

/// Publisher device identity block. Renamed from `Me` in 0.4.3a1
/// (the corresponding yaml key flipped from `me:` to `device:`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// `did:key:z…` of this party's device key.
    pub device_identity: String,
}

/// Recipient specification inside a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRecipient {
    /// Recipient device identity (`did:key:z…`). Renamed from `did`
    /// in 0.4.3a1 to match the canonical role vocabulary.
    #[serde(alias = "did")]
    pub recipient_identity: String,
    /// Reader-key file path (relative to keystore). Written by the legacy
    /// bgw cipher; kept so old yamls still parse.
    #[serde(default)]
    pub key: Option<String>,
    /// JWE X25519 public key as standard base64.
    #[serde(default)]
    pub pub_b64: Option<String>,
}

/// Per-group cipher configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSpec {
    /// `"private"` or `"public"`.
    #[serde(default = "default_private")]
    pub policy: String,
    /// Cipher name for this group.
    pub cipher: String,
    /// Declared recipients (used at ceremony setup; run-time cipher loads its own state files).
    #[serde(default)]
    pub recipients: Vec<GroupRecipient>,
    /// Recipient pool size. Written into ceremony yamls and admin events
    /// for schema stability; no current cipher consumes it.
    #[serde(default)]
    pub pool_size: Option<u32>,
    /// Incremented when keys rotate; feeds into HKDF info for index-key derivation.
    #[serde(default)]
    pub index_epoch: u64,
    /// Field names this group encrypts. Canonical multi-group routing
    /// source of truth: a field listed under N groups is encrypted into
    /// all N groups' payloads. Skipped on serialize when empty so old
    /// yamls that omit it stay byte-identical on round-trip.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    /// Default AAD (governance/policy marker) bound to this group's body on
    /// every emit and overlaid by any per-emit marker. A flat mapping of
    /// string keys to scalar values. When empty (the default) the group
    /// binds no marker and seals byte-identically to a no-AAD group.
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub aad: Map<String, Value>,
}

/// Per-field group routing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldRoute {
    /// Group name to route this field into.
    pub group: String,
}

/// LLM classifier block (stubbed on the Rust side — classification stays Python).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LlmClassifier {
    /// Whether the classifier is on.
    #[serde(default)]
    pub enabled: bool,
    /// Provider identifier.
    #[serde(default)]
    pub provider: String,
    /// Model identifier.
    #[serde(default)]
    pub model: String,
}

/// Root of the parsed tn.yaml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Ceremony metadata.
    pub ceremony: Ceremony,
    /// Project-level vault settings.
    #[serde(default)]
    pub vault: Vault,
    /// Whether the source YAML explicitly declared a `vault:` block.
    #[serde(skip)]
    pub vault_declared: bool,
    /// Main log destination. Optional in yaml (defaults to `./.tn/logs/tn.ndjson`
    /// relative to the yaml dir) for backwards compatibility with pre-existing
    /// ceremony files.
    #[serde(default = "default_logs")]
    pub logs: Logs,
    /// Keystore location.
    pub keystore: Keystore,
    /// Publisher device identity.
    pub device: Device,
    /// Fields that should always be emitted in the clear.
    #[serde(default)]
    pub public_fields: Vec<String>,
    /// Default policy for unclassified fields.
    #[serde(default = "default_private")]
    pub default_policy: String,
    /// Named groups keyed by group name.
    pub groups: BTreeMap<String, GroupSpec>,
    /// Optional per-field group routing.
    #[serde(default)]
    pub fields: BTreeMap<String, FieldRoute>,
    /// Optional LLM classifier config.
    #[serde(default)]
    pub llm_classifier: LlmClassifier,
    /// Handler specs (opaque for the Rust side — left to the host to interpret).
    #[serde(default)]
    pub handlers: Vec<serde_yml::Value>,
}

impl Config {
    /// Return the canonical project-level vault view, bridging legacy
    /// `ceremony.linked_*` fields when the new `vault:` block is absent.
    #[must_use]
    pub fn normalized_vault(&self) -> Vault {
        if self.vault_declared || self.vault.enabled || self.vault.url.is_some() {
            return Vault {
                enabled: self.vault.enabled,
                url: self.vault.url.clone(),
                linked_project_id: self.vault.linked_project_id.clone(),
                autosync: if self.vault.enabled {
                    self.vault.autosync
                } else {
                    false
                },
                sync_interval_seconds: self.vault.sync_interval_seconds,
            };
        }
        let legacy_url = self
            .ceremony
            .linked_vault
            .as_ref()
            .and_then(|s| non_empty_string(s));
        let legacy_project_id = self
            .ceremony
            .linked_project_id
            .as_ref()
            .and_then(|s| non_empty_string(s));
        Vault {
            enabled: legacy_url.is_some(),
            url: legacy_url,
            linked_project_id: legacy_project_id,
            autosync: self.ceremony.linked_vault.is_some(),
            sync_interval_seconds: default_vault_sync_interval_seconds(),
        }
    }

    /// Build the inverted multi-group field routing map.
    ///
    /// The new canonical source of truth is each group's own
    /// ``fields:`` list inside ``groups[<g>]``. A field listed under N
    /// groups is encrypted into all N groups' payloads. The returned
    /// list per field is sorted alphabetically + deduplicated so
    /// canonical envelope encoding stays stable across SDKs regardless
    /// of yaml key order.
    ///
    /// Back-compat: if no group declares ``fields:`` we fall through
    /// to the legacy flat ``fields:`` block (each field maps to one
    /// group). A ``tracing::warn!`` deprecation message is emitted in
    /// that case.
    ///
    /// # Errors
    ///
    /// Returns an error if a field is routed to a group that doesn't
    /// exist, or if the same field appears under both ``public_fields``
    /// and a group's ``fields`` list (ambiguous: is it public or
    /// encrypted?).
    pub fn field_to_groups(&self) -> Result<BTreeMap<String, Vec<String>>> {
        let any_group_declares_fields = self.groups.values().any(|g| !g.fields.is_empty());
        let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();

        if any_group_declares_fields {
            for (gname, gspec) in &self.groups {
                for fname in &gspec.fields {
                    out.entry(fname.clone()).or_default().push(gname.clone());
                }
            }
        } else if !self.fields.is_empty() {
            log::warn!(
                "the flat top-level `fields:` block is deprecated; declare \
                 field membership inside each group as `groups[<name>].fields: \
                 [...]`. The flat form supports only one group per field and \
                 will be removed in a future release."
            );
            for (fname, route) in &self.fields {
                out.entry(fname.clone())
                    .or_default()
                    .push(route.group.clone());
            }
        }

        // Validate: every routed group must exist.
        for (fname, gnames) in &out {
            for gname in gnames {
                if !self.groups.contains_key(gname) {
                    return Err(Error::Yaml(format!(
                        "field {fname:?} routed to unknown group {gname:?} \
                         (known groups: {:?})",
                        self.groups.keys().collect::<Vec<_>>()
                    )));
                }
            }
        }

        // Validate: a field cannot be both public and group-routed.
        let public: std::collections::BTreeSet<&String> = self.public_fields.iter().collect();
        let overlap: Vec<&String> = out.keys().filter(|f| public.contains(f)).collect();
        if !overlap.is_empty() {
            return Err(Error::Yaml(format!(
                "fields {overlap:?} appear in both public_fields and a \
                 group's fields: list. A field is either public (plaintext \
                 on the envelope) or encrypted into one or more groups, \
                 never both."
            )));
        }

        // Sort + dedupe each list deterministically.
        for gnames in out.values_mut() {
            gnames.sort();
            gnames.dedup();
        }

        Ok(out)
    }
}

fn non_empty_string(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Parse a tn.yaml document from a string.
///
/// Enforces the reserved-namespace rule (per 2026-04-25 read-ergonomics
/// spec §2.2): user-declared group names starting with `tn.` are rejected
/// with [`Error::ReservedGroupName`] except for the protocol-injected
/// `tn.agents` group.
///
/// **Does not resolve `extends:`.** Use [`parse_with_extends`] (or [`load`])
/// when the yaml may carry `extends: <relpath>` and you need the merged
/// view; this entry point is for self-contained yamls only (round-trip
/// tests, fixtures, callers that already inlined the parent).
pub fn parse(yaml: &str) -> Result<Config> {
    let value: serde_yml::Value =
        serde_yml::from_str(yaml).map_err(|e| Error::Yaml(e.to_string()))?;
    let vault_declared = match &value {
        serde_yml::Value::Mapping(map) => {
            map.contains_key(&serde_yml::Value::String("vault".into()))
        }
        _ => false,
    };
    let mut cfg: Config = serde_yml::from_value(value).map_err(|e| Error::Yaml(e.to_string()))?;
    cfg.vault_declared = vault_declared;
    if cfg.vault_declared {
        apply_vault_block_defaults(&mut cfg.vault, yaml);
        if cfg.vault.enabled && cfg.vault.url.is_none() {
            return Err(Error::InvalidConfig(
                "vault.enabled=true requires vault.url".into(),
            ));
        }
    }
    for gname in cfg.groups.keys() {
        if gname.starts_with("tn.") && gname != "tn.agents" {
            return Err(Error::ReservedGroupName {
                name: gname.clone(),
            });
        }
    }
    Ok(cfg)
}

fn apply_vault_block_defaults(vault: &mut Vault, yaml: &str) {
    let vault_lines: Vec<&str> = yaml
        .lines()
        .skip_while(|line| {
            let trimmed = line.trim();
            trimmed.is_empty() || trimmed.starts_with('#') || !trimmed.starts_with("vault:")
        })
        .skip(1)
        .take_while(|line| {
            line.starts_with(' ') || line.starts_with('\t') || line.trim().is_empty()
        })
        .collect();
    let enabled_declared = vault_lines
        .iter()
        .any(|line| line.trim_start().starts_with("enabled:"));
    if !enabled_declared {
        vault.enabled = true;
    }
    let autosync_declared = vault_lines
        .iter()
        .any(|line| line.trim_start().starts_with("autosync:"));
    if !autosync_declared {
        vault.autosync = vault.enabled;
    }
}

// ---------------------------------------------------------------------------
// extends: resolution
//
// Mirrors `python/tn/config.py::_resolve_extends` and
// `ts-sdk/src/runtime/config.ts::resolveExtends`. A child yaml that
// declares `extends: <relpath>` inherits identity, keystore, groups,
// recipients, and other parent-owned blocks from the referenced parent.
// Stream yamls written by the Python/TS multi-ceremony layer
// (`createFreshCeremony` for non-default streams) are minimal — they
// carry only `extends:` plus per-stream overrides (ceremony.profile,
// logs.path, handlers) and rely on this resolver to fill in the rest.
//
// Merge rules (must stay in lockstep with the Python + TS implementations):
//   - parent-owned keys (me, keystore, groups, fields, public_fields,
//     default_policy, llm_classifier): parent wins; child override is
//     dropped silently in Rust (Python logs a warning — Rust doesn't
//     have an equivalent ergonomic logger plumbed through here, so we
//     stay silent and match the on-disk merged shape).
//   - `ceremony`: shallow-merged per subfield, child wins.
//   - `handlers`: child replaces parent when declared, including [].
//   - all other top-level keys: child wins if set, else parent's.
//
// Path absolutization: parent's relative paths in `keystore.path`,
// `logs.path`, `handlers[*].path`, and `ceremony.admin_log_location` are
// converted to absolute paths rooted at the parent's directory before
// merge, so they survive the merge into the child's coordinate system
// (the child yaml typically lives in a sibling directory and would
// otherwise resolve those paths against its own dir).
// ---------------------------------------------------------------------------

/// Parent-owned top-level keys: child can never override.
const PARENT_OWNED_KEYS: &[&str] = &[
    "device",
    "keystore",
    "groups",
    "fields",
    "public_fields",
    "default_policy",
    "llm_classifier",
];

/// Maximum depth of an `extends:` chain. Belt-and-suspenders alongside
/// the path-based cycle check: in practice chains are 0–1 deep (a
/// stream extends the default ceremony, period). 8 is a generous
/// cap that still surfaces accidental recursion as a clean error.
const MAX_EXTENDS_DEPTH: usize = 8;

/// Cross-platform "is this absolute": recognises both POSIX absolute
/// paths (leading `/`) and Windows drive-letter paths (`C:\…` / `C:/…`)
/// regardless of the target `std::path` semantics. wasm32 builds use
/// Unix path rules which would otherwise mis-classify Windows paths
/// passed through from a Node host as relative, double-joining them
/// onto the yaml directory and breaking `extends:` chains under
/// Windows.
fn is_absolute_xplat(p: &str) -> bool {
    if Path::new(p).is_absolute() {
        return true;
    }
    let bytes = p.as_bytes();
    if bytes.len() >= 3 {
        let drive = bytes[0];
        if (drive.is_ascii_alphabetic())
            && bytes[1] == b':'
            && (bytes[2] == b'/' || bytes[2] == b'\\')
        {
            return true;
        }
    }
    false
}

fn absolutize_path_str(p: &str, base: &Path) -> String {
    let pp = Path::new(p);
    let joined = if is_absolute_xplat(p) {
        pp.to_path_buf()
    } else {
        base.join(pp)
    };
    normalize_path(&joined).to_string_lossy().into_owned()
}

/// Lexical-only path normalization: collapse `.` / `..` / repeated
/// separators without touching the filesystem. Equivalent to
/// `os.path.normpath` (Python) or `path.resolve` (Node) on absolute
/// inputs. We avoid `std::fs::canonicalize` here because (a) the merger
/// must work for paths whose parents may not yet exist on disk, and
/// (b) wasm targets can't canonicalize. Behavior matches what Python's
/// `Path.resolve(strict=False)` does for the path portion (without the
/// Windows-symlink prefixing).
fn normalize_path(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out: Vec<Component<'_>> = Vec::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                // Pop the last *normal* component if any, else keep `..`
                // (covers paths that ascend above the prefix — rare in
                // our merger but harmless).
                match out.last() {
                    Some(Component::Normal(_)) => {
                        out.pop();
                    }
                    _ => out.push(c),
                }
            }
            other => out.push(other),
        }
    }
    let mut buf = PathBuf::new();
    for c in out {
        buf.push(c.as_os_str());
    }
    buf
}

/// Walk `parent_doc` (the merged-but-pre-merge-into-child view) and
/// rewrite relative paths to be absolute under `parent_dir`. Mirrors
/// `python/tn/config.py::_absolutize_parent_doc`.
fn absolutize_parent_doc(parent_doc: &mut serde_yml::Mapping, parent_dir: &Path) {
    if let Some(serde_yml::Value::Mapping(ks)) = parent_doc.get_mut("keystore") {
        if let Some(serde_yml::Value::String(p)) = ks.get_mut("path") {
            *p = absolutize_path_str(p, parent_dir);
        }
    }
    if let Some(serde_yml::Value::Mapping(lg)) = parent_doc.get_mut("logs") {
        if let Some(serde_yml::Value::String(p)) = lg.get_mut("path") {
            *p = absolutize_path_str(p, parent_dir);
        }
    }
    if let Some(serde_yml::Value::Mapping(cer)) = parent_doc.get_mut("ceremony") {
        if let Some(serde_yml::Value::String(loc)) = cer.get_mut("admin_log_location") {
            if loc != "main_log" {
                *loc = absolutize_path_str(loc, parent_dir);
            }
        }
    }
    if let Some(serde_yml::Value::Sequence(hs)) = parent_doc.get_mut("handlers") {
        for h in hs.iter_mut() {
            if let serde_yml::Value::Mapping(hm) = h {
                if let Some(serde_yml::Value::String(p)) = hm.get_mut("path") {
                    *p = absolutize_path_str(p, parent_dir);
                }
            }
        }
    }
}

/// Apply Python's merge rules (`_resolve_extends` body) to combine a
/// fully-resolved + absolutized `parent` mapping with the child's `doc`.
/// `doc` may still contain its own `extends:` key on entry — that's
/// dropped from the merged result.
fn merge_parent_into_child(
    parent: serde_yml::Mapping,
    child: &serde_yml::Mapping,
) -> serde_yml::Mapping {
    let mut merged = parent;
    for (key, child_val) in child {
        let Some(key_s) = key.as_str() else { continue };
        if key_s == "extends" {
            continue;
        }
        if PARENT_OWNED_KEYS.contains(&key_s) {
            // Parent owns it: if parent set the key, child is dropped.
            // If parent omitted it, child fills in.
            if merged.contains_key(key) {
                continue;
            }
            merged.insert(key.clone(), child_val.clone());
            continue;
        }
        if key_s == "ceremony" {
            let mut base: serde_yml::Mapping = match merged.remove("ceremony") {
                Some(serde_yml::Value::Mapping(m)) => m,
                _ => serde_yml::Mapping::new(),
            };
            if let serde_yml::Value::Mapping(child_cer) = child_val {
                for (ck, cv) in child_cer {
                    base.insert(ck.clone(), cv.clone());
                }
            }
            merged.insert(
                serde_yml::Value::String("ceremony".into()),
                serde_yml::Value::Mapping(base),
            );
            continue;
        }
        if key_s == "handlers" {
            let out: Vec<serde_yml::Value> = match child_val {
                serde_yml::Value::Sequence(s) => s.clone(),
                _ => Vec::new(),
            };
            merged.insert(
                serde_yml::Value::String("handlers".into()),
                serde_yml::Value::Sequence(out),
            );
            continue;
        }
        // Default: child wins outright.
        merged.insert(key.clone(), child_val.clone());
    }
    merged.remove("extends");
    merged
}

/// Recursive extends walker. `yaml_path` is the current yaml being
/// processed; `doc` is its already-parsed mapping (env-var-expanded);
/// `storage` is the I/O backend for reading parent yamls. Returns the
/// fully merged mapping with `extends:` removed.
fn resolve_extends_value(
    yaml_path: &Path,
    doc: serde_yml::Mapping,
    seen: &mut Vec<PathBuf>,
    depth: usize,
    storage: &dyn crate::storage::Storage,
) -> Result<serde_yml::Mapping> {
    let extends_v = match doc.get("extends") {
        Some(v) => v.clone(),
        None => return Ok(doc),
    };
    if depth >= MAX_EXTENDS_DEPTH {
        return Err(Error::InvalidConfig(format!(
            "{}: extends chain exceeds maximum depth {} (likely a cycle)",
            yaml_path.display(),
            MAX_EXTENDS_DEPTH,
        )));
    }
    let extends_str = match extends_v {
        serde_yml::Value::String(s) => s,
        other => {
            return Err(Error::InvalidConfig(format!(
                "{}: extends must be a string path (got {:?})",
                yaml_path.display(),
                other,
            )));
        }
    };
    let parent_dir = yaml_path.parent().unwrap_or(Path::new("."));
    let parent_path = parent_dir.join(&extends_str);

    // Cycle detection on the visited-path list. We compare against both
    // the raw parent_path and the current yaml_path so a back-edge is
    // caught regardless of where in the chain it loops to.
    if seen.iter().any(|p| paths_equal(p, &parent_path)) {
        return Err(Error::InvalidConfig(format!(
            "{}: extends cycle detected (parent {} already in chain). \
             extends: chains cannot loop back on themselves.",
            yaml_path.display(),
            parent_path.display(),
        )));
    }
    if !storage.exists(&parent_path) {
        return Err(Error::InvalidConfig(format!(
            "{}: extends target {} does not exist",
            yaml_path.display(),
            parent_path.display(),
        )));
    }
    let parent_bytes = storage.read_bytes(&parent_path).map_err(Error::Io)?;
    let parent_text = std::str::from_utf8(&parent_bytes).map_err(|e| {
        Error::InvalidConfig(format!(
            "{}: extends target {} is not valid UTF-8: {}",
            yaml_path.display(),
            parent_path.display(),
            e,
        ))
    })?;
    let parent_expanded = substitute_env_vars(parent_text, &parent_path)?;
    let parent_value: serde_yml::Value = serde_yml::from_str(&parent_expanded)
        .map_err(|e| Error::Yaml(format!("{}: {e}", parent_path.display())))?;
    let serde_yml::Value::Mapping(parent_doc) = parent_value else {
        return Err(Error::InvalidConfig(format!(
            "{}: expected top-level mapping",
            parent_path.display(),
        )));
    };

    seen.push(yaml_path.to_path_buf());
    let mut parent_resolved =
        resolve_extends_value(&parent_path, parent_doc, seen, depth + 1, storage)?;
    seen.pop();

    // Absolutize parent's relative paths against parent's directory
    // before merging into the child's coordinate system.
    let parent_dir_abs = parent_path.parent().unwrap_or(Path::new("."));
    absolutize_parent_doc(&mut parent_resolved, parent_dir_abs);

    Ok(merge_parent_into_child(parent_resolved, &doc))
}

/// Loose path equality good enough for cycle detection. We compare the
/// `Path::components()` view so trivial differences like trailing
/// separators don't fool the check. We do *not* canonicalize (no
/// filesystem dependency, no symlink resolution) — that's intentional:
/// the depth limit catches symlink loops we'd miss here.
fn paths_equal(a: &Path, b: &Path) -> bool {
    let acomp: Vec<_> = a.components().collect();
    let bcomp: Vec<_> = b.components().collect();
    acomp == bcomp
}

/// Parse a tn.yaml that may carry `extends: <relpath>`, resolving the
/// extends chain through `storage` (so wasm consumers route reads
/// through their JS-side callback).
///
/// `yaml_str` is the env-var-expanded text of the yaml at `yaml_path`.
/// `yaml_path` is used both as the base directory for resolving the
/// child's `extends:` and for error messages.
///
/// Merge semantics mirror `python/tn/config.py::_resolve_extends` and
/// `ts-sdk/src/runtime/config.ts::resolveExtends`. See the module-level
/// comment for the merge rules.
pub fn parse_with_extends(
    yaml_str: &str,
    yaml_path: &Path,
    storage: &dyn crate::storage::Storage,
) -> Result<Config> {
    let value: serde_yml::Value =
        serde_yml::from_str(yaml_str).map_err(|e| Error::Yaml(e.to_string()))?;
    let serde_yml::Value::Mapping(doc) = value else {
        return Err(Error::InvalidConfig(format!(
            "{}: expected top-level mapping",
            yaml_path.display(),
        )));
    };
    let merged = if doc.contains_key("extends") {
        let mut seen: Vec<PathBuf> = Vec::new();
        resolve_extends_value(yaml_path, doc, &mut seen, 0, storage)?
    } else {
        doc
    };
    let merged_str = serde_yml::to_string(&serde_yml::Value::Mapping(merged))
        .map_err(|e| Error::Yaml(e.to_string()))?;
    parse(&merged_str)
}

/// Load + parse a tn.yaml from disk, resolving `extends:` chains.
///
/// Env-var substitution (`${VAR}`, `${VAR:-default}`, `$${literal}`) runs
/// over the file contents before yaml parsing — see [`substitute_env_vars`].
/// `extends:` is resolved against the file's own directory via the
/// default `FsStorage` backend; use [`parse_with_extends`] directly to
/// inject a custom storage backend (wasm / in-memory tests).
#[cfg(feature = "fs")]
pub fn load(path: &Path) -> Result<Config> {
    let s = std::fs::read_to_string(path)?;
    let expanded = substitute_env_vars(&s, path)?;
    let storage = crate::storage::FsStorage::new();
    parse_with_extends(&expanded, path, &storage)
}

/// Serialize a Config back to YAML at `path`.
#[cfg(feature = "fs")]
pub fn save(cfg: &Config, path: &Path) -> Result<()> {
    let s = serde_yml::to_string(cfg).map_err(|e| Error::Yaml(e.to_string()))?;
    std::fs::write(path, s)?;
    Ok(())
}
