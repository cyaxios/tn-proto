//! tn.yaml parsing via serde_yml.
//!
//! Mirrors the schema emitted by `tn/config.py::create_fresh`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

use crate::{Error, Result};

/// Compose-style env-var substitution applied to the raw yaml *string*
/// before the yaml parser runs.
///
/// Mirrors `_substitute_env_vars` in `tn-protocol/python/tn/config.py`
/// and `substituteEnvVars` in `tn-protocol/ts-sdk/src/runtime/config.ts`.
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
    text[..offset.min(text.len())].bytes().filter(|&b| b == b'\n').count() + 1
}

/// Top-level ceremony metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ceremony {
    /// Ceremony identifier (e.g. `cer_abc123`).
    pub id: String,
    /// Ceremony mode: `"local"` or `"linked"`.
    #[serde(default = "default_local")]
    pub mode: String,
    /// Cipher name: `"btn"`, `"jwe"`, or `"bgw"`.
    pub cipher: String,
    /// Vault URL for linked-mode ceremonies.
    #[serde(default)]
    pub linked_vault: Option<String>,
    /// Project id for linked-mode ceremonies.
    #[serde(default)]
    pub linked_project_id: Option<String>,
    /// Sync logs flag for wallet-linked ceremonies.
    #[serde(default)]
    pub sync_logs: bool,
    /// Where to route `tn.*` protocol events: `"main_log"` or path template.
    #[serde(default = "default_pel")]
    pub protocol_events_location: String,
    /// Whether each emitted entry is signed by the publisher's Ed25519
    /// device key. `true` (default) produces fully attested logs. `false`
    /// skips the signature step — entries still carry row_hash + prev_hash
    /// for chain integrity, but lack identity attestation. Useful for
    /// high-throughput observability flows where batch-signing (RFC
    /// `2026-04-22-tn-transaction-protocol`) is not yet implemented.
    #[serde(default = "default_sign")]
    pub sign: bool,
    /// Active log-level threshold (AVL J3.2). One of "debug" / "info" /
    /// "warning" / "error", case-insensitive. ``"debug"`` (default)
    /// emits every verb; raising drops lower-priority emits before any
    /// work. Honored at init unless the caller already invoked
    /// [`Runtime::set_level`] programmatically. Empty string and
    /// missing key both leave the threshold at its current value.
    #[serde(default)]
    pub log_level: String,
}

fn default_local() -> String {
    "local".into()
}
fn default_pel() -> String {
    "main_log".into()
}
fn default_private() -> String {
    "private".into()
}
fn default_sign() -> bool {
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

/// Publisher identity hint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Me {
    /// `did:key:z…` of this party's device key.
    pub did: String,
}

/// Recipient specification inside a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRecipient {
    /// Recipient DID (`did:key:z…`).
    pub did: String,
    /// BGW reader-key file path (relative to keystore).
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
    /// Pool size for BGW (ignored by other ciphers).
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
    /// Main log destination. Optional in yaml (defaults to `./.tn/logs/tn.ndjson`
    /// relative to the yaml dir) for backwards compatibility with pre-existing
    /// ceremony files.
    #[serde(default = "default_logs")]
    pub logs: Logs,
    /// Keystore location.
    pub keystore: Keystore,
    /// Publisher identity.
    pub me: Me,
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
                out.entry(fname.clone()).or_default().push(route.group.clone());
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
        let overlap: Vec<&String> = out
            .keys()
            .filter(|f| public.contains(f))
            .collect();
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

/// Parse a tn.yaml document from a string.
///
/// Enforces the reserved-namespace rule (per 2026-04-25 read-ergonomics
/// spec §2.2): user-declared group names starting with `tn.` are rejected
/// with [`Error::ReservedGroupName`] except for the protocol-injected
/// `tn.agents` group.
pub fn parse(yaml: &str) -> Result<Config> {
    let cfg: Config = serde_yml::from_str(yaml).map_err(|e| Error::Yaml(e.to_string()))?;
    for gname in cfg.groups.keys() {
        if gname.starts_with("tn.") && gname != "tn.agents" {
            return Err(Error::ReservedGroupName {
                name: gname.clone(),
            });
        }
    }
    Ok(cfg)
}

/// Load + parse a tn.yaml from disk.
///
/// Env-var substitution (`${VAR}`, `${VAR:-default}`, `$${literal}`) runs
/// over the file contents before yaml parsing — see [`substitute_env_vars`].
pub fn load(path: &Path) -> Result<Config> {
    let s = std::fs::read_to_string(path)?;
    let expanded = substitute_env_vars(&s, path)?;
    parse(&expanded)
}

/// Serialize a Config back to YAML at `path`.
pub fn save(cfg: &Config, path: &Path) -> Result<()> {
    let s = serde_yml::to_string(cfg).map_err(|e| Error::Yaml(e.to_string()))?;
    std::fs::write(path, s)?;
    Ok(())
}
