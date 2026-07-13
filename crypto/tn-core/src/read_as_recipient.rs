//! Decrypt a foreign publisher's ndjson log with a kit dropped into a
//! local keystore directory by `Runtime::absorb`. Internal primitive: most
//! readers want the high-level API instead — see [`crate::Runtime`] for the
//! full read path (behind `tn.read()` / `tn read`). Reach here directly only
//! for a cross-publisher decrypt that bypasses your own ceremony setup.
//!
//! Mirrors Python `tn.read_as_recipient(log_path, keystore_dir, group=)`
//! and TS `readAsRecipient(logPath, keystorePath, opts?)`. Closes the
//! cross-binding gap surfaced by the cash-register Stage 6 + AVL J7
//! audits — Rust now has the same direct-decrypt verb its sibling
//! bindings ship.
//!
//! Dispatches on the kit file present in `keystore_path`:
//!
//! - `<group>.btn.mykit` → btn (subset-difference broadcast)
//! - `<group>.hibe.sk` plus its MPK/path → HIBE
//! - `<group>.jwe.mykey` → a precise unavailable-cipher error until the native
//!   JWE candidate lands
//!
//! Use this verb when the calling Rust app holds a kit handed to it via
//! a `kit_bundle` `.tnpkg` and needs to read another publisher's log.
//! It deliberately bypasses the full `Runtime` setup so cross-publisher
//! reads don't require a ceremony of your own.

use std::path::Path;

use serde_json::{Map, Value};

use crate::error::Result;

/// One decrypted entry from a foreign publisher's log. Mirrors the
/// shape that Python's `tn.read_as_recipient` and TS's
/// `readAsRecipient` yield.
#[derive(Debug, Clone)]
pub struct ForeignReadEntry {
    /// Raw envelope JSON (public fields, signatures, hashes, group
    /// ciphertext blocks). Same shape as anything `Runtime::read`
    /// would produce.
    pub envelope: Map<String, Value>,
    /// Decrypted group plaintext, keyed by group name. Only the group
    /// we have a kit for is present. A group whose ciphertext we
    /// couldn't decrypt is recorded with the marker key
    /// `"$no_read_key"` mapping to `true`.
    pub plaintext: Map<String, Value>,
    /// Per-row validity. `signature` requires both a matching row hash and a
    /// valid signature from `device_identity`; `chain` is per-event-type
    /// `prev_hash` continuity.
    pub valid: ForeignValid,
}

/// Per-row validity flags for a foreign-read entry.
#[derive(Debug, Clone, Copy)]
pub struct ForeignValid {
    /// True iff the envelope's signature verifies under the publisher's `did`.
    pub signature: bool,
    /// True iff the envelope's `prev_hash` matches the previous
    /// envelope's `row_hash` for the same `event_type`.
    pub chain: bool,
}

/// Options controlling the foreign-read iteration.
#[derive(Debug, Clone)]
pub struct ReadAsRecipientOptions {
    /// Group name to decrypt. Default `"default"`.
    pub group: String,
    /// Verify per-row signatures (slower but catches forgery).
    /// Default `true`. Off for debug-only fast-paths where you only
    /// care about plaintext.
    pub verify_signatures: bool,
}

impl Default for ReadAsRecipientOptions {
    fn default() -> Self {
        Self {
            group: "default".into(),
            verify_signatures: true,
        }
    }
}

/// Iterate decrypted entries from `log_path` using a kit found in
/// `keystore_path`. Mirrors Python's `tn.read_as_recipient` and TS's
/// `readAsRecipient`. (AVL J7 / cash-register S6.2 cross-binding port.)
///
/// # Errors
///
/// - `Error::InvalidConfig` if no BTN/HIBE reader material for `opts.group`
///   exists in `keystore_path`, or the selected material is native JWE.
/// - `Error::Io` for file read failures.
/// - `Error::Json` for malformed JSON lines.
pub fn read_as_recipient(
    log_path: &Path,
    keystore_path: &Path,
    opts: ReadAsRecipientOptions,
) -> Result<Vec<ForeignReadEntry>> {
    let rows = crate::runtime::read_recipient_rows(log_path, keystore_path, &opts.group)?;
    Ok(rows
        .into_iter()
        .filter_map(|row| adapt_recipient_row(row, &opts))
        .collect())
}

fn adapt_recipient_row(
    row: crate::runtime::RecipientRow,
    options: &ReadAsRecipientOptions,
) -> Option<ForeignReadEntry> {
    let envelope = row.entry.envelope.as_object()?.clone();
    let mut plaintext = Map::new();
    if let Some(value) = row.entry.plaintext_per_group.get(&options.group) {
        plaintext.insert(options.group.clone(), value.clone());
    }
    Some(ForeignReadEntry {
        envelope,
        plaintext,
        valid: ForeignValid {
            signature: !options.verify_signatures || row.signature,
            chain: row.chain,
        },
    })
}
