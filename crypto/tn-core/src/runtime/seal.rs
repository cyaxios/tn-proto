//! `Runtime::seal` — portable sealed objects (the write half of
//! `tn.seal` / `tn.unseal`).
//!
//! A sealed object is a standalone envelope: the same wire schema
//! [`Runtime::emit`] writes, built and RETURNED instead of appended to
//! the log. Fields route into groups per the yaml and encrypt exactly
//! as an emit would (same sort / index-token / AAD-merge / encrypt
//! pipeline), but the standalone conventions differ: `sequence` is 0,
//! `prev_hash` and `level` are `""`, the reserved public marker
//! `tn_sealed: 1` is added, the object is ALWAYS signed, and the
//! ceremony's chain state is never touched.
//!
//! Mirrors `python/tn/seal.py::seal` step-for-step; the pure shape /
//! verify helpers live in [`crate::sealed_object`].

mod candidates;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::chain::{compute_row_hash, RowHashInput};
use crate::cipher::GroupCipher;
use crate::envelope::{build_envelope, EnvelopeInput};
use crate::sealed_object::{
    aad_bytes_for, extract_group_blocks, parse_sealed_source, reject_fragile_public,
    require_envelope_shape, verify_sealed, GroupBlock, SealedObjectLine, SealedValid,
    ENVELOPE_RESERVED, SEALED_RECEIPT_EVENT, TN_SEALED_KEY,
};
use crate::signing::signature_b64;
use crate::{Error, Result};

use super::util::{current_timestamp, validate_event_type};
use super::Runtime;
use candidates::{
    discover_keybag, jwe_reader_candidate, load_recipient_candidates, unusable_keystore_kinds,
};

/// Options for [`Runtime::seal`].
pub struct SealOptions {
    /// Chain a `tn.object.sealed` receipt row through the normal
    /// runtime emit path (default `true`). Receipt failures PROPAGATE —
    /// the caller asked for a receipt, so a silently missing one would
    /// break the guarantee.
    pub receipt: bool,
    /// Per-seal AAD marker map, overlaid onto each group's configured
    /// default (per-seal wins per key) and bound into the sealed
    /// bodies. Echoed under the public `tn_aad` field when non-empty.
    pub aad: Map<String, Value>,
}

impl Default for SealOptions {
    fn default() -> Self {
        Self {
            receipt: true,
            aad: Map::new(),
        }
    }
}

impl Runtime {
    /// Seal `fields` into a portable attested object (standalone
    /// envelope). Mirrors `python/tn/seal.py::seal`; never touches
    /// [`ChainState`](crate::chain::ChainState).
    ///
    /// Returns a [`SealedObjectLine`]: the parsed envelope plus the
    /// compact wire JSON WITHOUT a trailing newline (Python's
    /// `str(sealed)` has none). Callers transport `wire` verbatim —
    /// never a re-serialization.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when `object_type` is invalid, a field
    /// is named `tn_sealed`, a public field is an object carrying a
    /// `"ciphertext"` key (the wire is self-describing; unseal would
    /// misread it as a group block), a field has no group route, or a
    /// public value would not survive a foreign JSON round-trip (see
    /// [`reject_fragile_public`]). Cipher / JSON / receipt-emit errors
    /// propagate.
    ///
    /// # Panics
    ///
    /// Panics if an internal group-state lock is poisoned.
    pub fn seal(
        &self,
        object_type: &str,
        fields: Map<String, Value>,
        opts: &SealOptions,
    ) -> Result<SealedObjectLine> {
        validate_event_type(object_type)?;
        if fields.contains_key(TN_SEALED_KEY) {
            return Err(Error::InvalidConfig(
                "tn_sealed is a reserved sealed-object marker; rename the field".into(),
            ));
        }
        // (Python applies _coerce_for_wire here — bytes/Decimal/datetime
        // to wire shapes. At this boundary fields are already JSON
        // values, so there is nothing to coerce.)

        // 1. Classify public vs group buckets. Direct call — unlike
        //    emit there is NO run_id injection and NO agent-policy
        //    splice (seal.py mirrors _emit_locked's classification
        //    minus the context merge).
        let (mut public_out, per_group) = self.classify_fields(fields)?;
        for (k, v) in &public_out {
            if v.as_object().is_some_and(|o| o.contains_key("ciphertext")) {
                // The wire is self-describing: unseal treats any object
                // value carrying a "ciphertext" key as an encrypted
                // group block, so a public field shaped like that could
                // never round-trip.
                return Err(Error::InvalidConfig(format!(
                    "public field {k:?} is a dict containing a 'ciphertext' \
                     key; unseal would misread it as an encrypted group \
                     block. Rename the inner key or route the field into \
                     a group."
                )));
            }
        }

        // 2–3. Index tokens + AAD bind + encrypt per group — the emit
        //      path's pipeline, reused. need_row_hash=true: a sealed
        //      object is always hashed and signed.
        let (group_inputs, group_payloads, aad_echo) =
            self.encrypt_groups(per_group, &opts.aad, true)?;

        // 4. tn_aad echo — identical encoding to emit_inner: the
        //    canonical bytes of the {group: marker} echo object as a
        //    UTF-8 STRING public field, so it feeds row_hash and the
        //    signature (an authenticated echo).
        if !aad_echo.is_empty() {
            let bytes = crate::canonical::canonical_bytes(&Value::Object(aad_echo))?;
            let s = String::from_utf8(bytes)
                .map_err(|_| Error::Internal("tn_aad canonical bytes not utf-8".into()))?;
            public_out.insert("tn_aad".to_string(), Value::String(s));
        }
        // Detachment marker — a number so str(value) in the row-hash
        // preimage renders identically in every SDK implementation.
        public_out.insert(TN_SEALED_KEY.to_string(), Value::Number(1.into()));

        // 5. A sealed object travels through arbitrary intermediaries
        //    (LLM tool boundaries, browsers) which reserialize JSON.
        //    Refuse public values such a round-trip would silently
        //    mutate, so the failure lands here instead of at a remote
        //    unseal.
        reject_fragile_public(&public_out)?;

        // 6. Standalone identity. Python uses uuid4 here (not the emit
        //    path's time-sortable v7) — a sealed object is not a log
        //    row; match it.
        let timestamp = current_timestamp();
        let event_id = Uuid::new_v4().to_string();

        // 7. Hash + sign, with the standalone sentinels (sequence is
        //    excluded from the preimage; prev_hash and level are "").
        //    Always signed, regardless of the ceremony's sign flag.
        let public_bmap: BTreeMap<String, Value> = public_out.clone().into_iter().collect();
        let row_hash = compute_row_hash(&RowHashInput {
            device_identity: self.device.did(),
            timestamp: &timestamp,
            event_id: &event_id,
            event_type: object_type,
            level: "",
            prev_hash: "",
            public_fields: &public_bmap,
            groups: &group_inputs,
        });
        let sig = self.device.sign(row_hash.as_bytes());
        let sig_b64 = signature_b64(&sig);

        // 8. Envelope build. build_envelope appends the log's trailing
        //    newline; the sealed wire artifact carries none.
        let group_names: Vec<String> = group_payloads.keys().cloned().collect(); // BTreeMap: sorted
        let mut wire = build_envelope(EnvelopeInput {
            device_identity: self.device.did(),
            timestamp: &timestamp,
            event_id: &event_id,
            event_type: object_type,
            level: "",
            sequence: 0,
            prev_hash: "",
            row_hash: &row_hash,
            signature_b64: &sig_b64,
            public_fields: public_out,
            group_payloads,
        })?;
        if wire.ends_with('\n') {
            wire.pop();
        }
        let envelope: Map<String, Value> = serde_json::from_str(&wire)?;

        // 9. Receipt row through the normal emit path (PEL routing,
        //    schema-free: tn.object.sealed is not in the admin
        //    catalog). Errors PROPAGATE.
        if opts.receipt {
            let mut rfields = Map::new();
            rfields.insert("object_id".to_string(), Value::String(row_hash));
            rfields.insert(
                "object_type".to_string(),
                Value::String(object_type.to_string()),
            );
            rfields.insert(
                "groups".to_string(),
                Value::Array(group_names.into_iter().map(Value::String).collect()),
            );
            self.emit("info", SEALED_RECEIPT_EVENT, rfields)?;
        }

        Ok(SealedObjectLine { envelope, wire })
    }

    /// Verify a sealed object and open every group block a held key
    /// fits. Mirrors `python/tn/seal.py::unseal`.
    ///
    /// `source` is the sealed object's wire JSON text (the original
    /// wire string is the safe input — a foreign re-serialization may
    /// have mutated fragile values).
    ///
    /// No key fitting is NOT an error: the verified public frame comes
    /// back with the blocks left sealed (listed in
    /// [`UnsealOutcome::hidden_groups`] / [`UnsealOutcome::sealed_blocks`]).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] (`kind: "sealed object"`) for input that is
    /// not a sealed-object envelope at all;
    /// [`Error::SealedObjectVerify`] when `opts.verify` is set and a
    /// check fails; [`Error::InvalidConfig`] when `opts.as_recipient`
    /// names a directory holding no key file for `opts.group`.
    ///
    /// # Panics
    ///
    /// Panics if an internal group-state lock is poisoned.
    pub fn unseal(&self, source: &str, opts: &UnsealOptions) -> Result<UnsealOutcome> {
        let env = parse_sealed_source(source)?;
        self.unseal_env(env, opts)
    }

    /// As [`Runtime::unseal`] but from an already-parsed envelope map
    /// (the dict-source shape Python accepts).
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::unseal`].
    ///
    /// # Panics
    ///
    /// Panics if an internal group-state lock is poisoned.
    pub fn unseal_env(
        &self,
        env: Map<String, Value>,
        opts: &UnsealOptions,
    ) -> Result<UnsealOutcome> {
        let env = require_envelope_shape(env)?;
        let blocks = extract_group_blocks(&env)?;
        let valid = verify_gate(&env, &blocks, opts.verify)?;
        let env_value = Value::Object(env);

        let mut plaintext: BTreeMap<String, Value> = BTreeMap::new();
        let walk_keystore: &Path = if let Some(dir) = &opts.as_recipient {
            // Single-kit override: load every cipher candidate for
            // `opts.group` from that directory and decrypt only that
            // group. Nothing to open means nothing to load — skip the
            // keystore entirely (mirrors seal.py:463-472).
            if blocks.contains_key(&opts.group) {
                if let Some(block) = blocks.get(&opts.group) {
                    for cipher in load_recipient_candidates(dir, &opts.group)? {
                        if try_open(
                            &opts.group,
                            block,
                            cipher.as_ref(),
                            &env_value,
                            &mut plaintext,
                        ) {
                            break;
                        }
                    }
                }
            }
            dir
        } else {
            // Pass 1: own-ceremony group ciphers (publisher side).
            for (gname, block) in &blocks {
                if let Some(gstate_arc) = self.groups.get(gname) {
                    let gstate = gstate_arc.read().expect("group state RwLock poisoned");
                    try_open(
                        gname,
                        block,
                        gstate.cipher.as_ref(),
                        &env_value,
                        &mut plaintext,
                    );
                }
            }
            // Pass 2: the device key opens any JWE wrap naming its DID.
            let jwe = jwe_reader_candidate(&self.device)?;
            for (gname, block) in &blocks {
                if !plaintext.contains_key(gname) {
                    try_open(gname, block, jwe.as_ref(), &env_value, &mut plaintext);
                }
            }
            // Pass 3: group-specific key-bag (own kits + absorbed kits).
            let bag = discover_keybag(&self.keystore);
            for (gname, block) in &blocks {
                if plaintext.contains_key(gname) {
                    continue;
                }
                for cipher in bag.get(gname).map_or(&[][..], Vec::as_slice) {
                    if try_open(gname, block, cipher.as_ref(), &env_value, &mut plaintext) {
                        break;
                    }
                }
            }
            &self.keystore
        };

        Ok(build_outcome(
            env_value,
            blocks,
            plaintext,
            valid,
            walk_keystore,
        ))
    }
}

/// Options for [`Runtime::unseal`].
pub struct UnsealOptions {
    /// Verify signature + row hash before decrypting (default `true`).
    /// A failed check raises [`Error::SealedObjectVerify`]; with
    /// `verify: false` both [`SealedValid`] flags report `false` and
    /// the walk proceeds.
    pub verify: bool,
    /// Bring-your-own-kit override: a directory holding recipient key
    /// files (`<group>.btn.mykit` / `local.private` for JWE /
    /// `<group>.hibe.sk`). When set, only [`UnsealOptions::group`] is
    /// decrypted and the runtime's own groups/keystore are not
    /// consulted.
    pub as_recipient: Option<PathBuf>,
    /// The group the `as_recipient` override opens (default
    /// `"default"`). Ignored on the default walk, which tries every
    /// block.
    pub group: String,
}

impl Default for UnsealOptions {
    fn default() -> Self {
        Self {
            verify: true,
            as_recipient: None,
            group: "default".to_string(),
        }
    }
}

/// One group block [`Runtime::unseal`] could not open, with everything
/// a managed cipher needs for a second-pass decrypt:
/// the wire ciphertext, the reconstructed AAD bytes, and which cipher
/// kinds have key files on disk that this build could not use.
#[derive(Debug, Clone)]
pub struct SealedGroupInfo {
    /// Group name.
    pub name: String,
    /// The block's ciphertext exactly as carried on the wire
    /// (standard base64).
    pub ciphertext_b64: String,
    /// The block's field-hash tokens, as carried on the wire.
    pub field_hashes: BTreeMap<String, String>,
    /// `base64(aad_bytes_for(envelope, name))` — the byte-identical
    /// AAD a second-pass decrypt must supply. `""` when the object
    /// bound no marker for this group.
    pub aad_b64: String,
    /// Cipher kinds with key files on disk for this group that this
    /// build could NOT use: a legacy `"jwe"` key file, or `"hibe"`
    /// when the `hibe` feature is off. Native JWE uses `local.private`.
    pub keystore_candidates: Vec<String>,
}

/// Result of [`Runtime::unseal`] / [`unseal_as_recipient`].
#[derive(Debug, Clone)]
pub struct UnsealOutcome {
    /// The envelope, wire-faithful (keeps the `tn_sealed` marker).
    pub envelope: Map<String, Value>,
    /// Opened groups only: group name → decrypted JSON body.
    pub plaintext: BTreeMap<String, Value>,
    /// Which integrity checks passed. Both `false` when
    /// [`UnsealOptions::verify`] was off.
    pub valid: SealedValid,
    /// Blocks present in the envelope but not opened, sorted.
    pub hidden_groups: Vec<String>,
    /// Per-unopened-block decrypt material — the managed-cipher
    /// second-pass seam.
    pub sealed_blocks: Vec<SealedGroupInfo>,
    /// Entry-style merge: opened group plaintexts (alphabetical,
    /// last-write-wins), then non-reserved non-block public extras.
    /// The `tn_sealed` wire marker is dropped (mirrors Python's
    /// `Entry.fields`).
    pub fields: Map<String, Value>,
}

/// Verify a sealed object and open the named group with keys from a
/// bare keystore directory — no ceremony or [`Runtime`] required.
/// Backs the `as_recipient` path (mirrors `tn.unseal(...,
/// as_recipient=dir, group=...)` called without an active ceremony).
///
/// # Errors
///
/// Same taxonomy as [`Runtime::unseal`]: `Malformed` for non-envelope
/// input, `SealedObjectVerify` on failed verification,
/// `InvalidConfig` when `keystore` holds no key file for `group`.
pub fn unseal_as_recipient(
    source: &str,
    keystore: &Path,
    group: &str,
    verify: bool,
) -> Result<UnsealOutcome> {
    let env = parse_sealed_source(source)?;
    let blocks = extract_group_blocks(&env)?;
    let valid = verify_gate(&env, &blocks, verify)?;
    let env_value = Value::Object(env);

    let mut plaintext: BTreeMap<String, Value> = BTreeMap::new();
    if let Some(block) = blocks.get(group) {
        for cipher in load_recipient_candidates(keystore, group)? {
            if try_open(group, block, cipher.as_ref(), &env_value, &mut plaintext) {
                break;
            }
        }
    }
    Ok(build_outcome(env_value, blocks, plaintext, valid, keystore))
}

/// Run [`verify_sealed`] when `verify` is set and promote a failed
/// check to [`Error::SealedObjectVerify`]. `verify: false` returns the
/// both-false default and the caller proceeds (mirrors
/// seal.py:310-345, including the failed-check order:
/// signature first, then row_hash — Python's `valid` dict insertion
/// order).
fn verify_gate(
    env: &Map<String, Value>,
    blocks: &BTreeMap<String, GroupBlock>,
    verify: bool,
) -> Result<SealedValid> {
    if !verify {
        return Ok(SealedValid::default());
    }
    let valid = verify_sealed(env, blocks);
    let mut failed: Vec<String> = Vec::new();
    if !valid.signature {
        failed.push("signature".to_string());
    }
    if !valid.row_hash {
        failed.push("row_hash".to_string());
    }
    if !failed.is_empty() {
        return Err(Error::SealedObjectVerify {
            failed_checks: failed,
            sequence: env.get("sequence").and_then(Value::as_u64).unwrap_or(0),
            event_type: env
                .get("event_type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        });
    }
    Ok(valid)
}

/// Try one cipher candidate on one block: decrypt with the group's
/// reconstructed AAD, parse the plaintext as JSON, and record it.
/// ANY candidate failure (wrong key, AEAD mismatch, non-JSON
/// plaintext) is swallowed and the walk continues — a non-fitting key
/// must not abort the walk (mirrors seal.py:454-461).
fn try_open(
    gname: &str,
    block: &GroupBlock,
    cipher: &dyn GroupCipher,
    env: &Value,
    plaintext: &mut BTreeMap<String, Value>,
) -> bool {
    let aad = aad_bytes_for(env, gname);
    let Ok(pt) = cipher.decrypt_with_aad(&block.ciphertext, &aad) else {
        return false;
    };
    let Ok(body) = serde_json::from_slice::<Value>(&pt) else {
        return false;
    };
    plaintext.insert(gname.to_string(), body);
    true
}

/// Assemble the [`UnsealOutcome`]: hidden groups (blocks not opened,
/// sorted), the sealed-blocks seam, and the Entry-style `fields` merge
/// mirroring `python/tn/_entry.py::Entry.from_raw` — opened plaintexts
/// alphabetically (last-write-wins), then non-reserved non-block
/// public extras with the `tn_sealed` marker dropped, then the
/// `run_id` / `message` slots Python pops out of `fields`.
fn build_outcome(
    env_value: Value,
    blocks: BTreeMap<String, GroupBlock>,
    plaintext: BTreeMap<String, Value>,
    valid: SealedValid,
    walk_keystore: &Path,
) -> UnsealOutcome {
    let Value::Object(env) = env_value else {
        unreachable!("build_outcome is only called with an object envelope");
    };

    // Blocks present but not opened — BTreeMap keys iterate sorted.
    let hidden_groups: Vec<String> = blocks
        .keys()
        .filter(|g| !plaintext.contains_key(*g))
        .cloned()
        .collect();

    let env_for_aad = Value::Object(env.clone());
    let sealed_blocks: Vec<SealedGroupInfo> = hidden_groups
        .iter()
        .map(|g| {
            let b = &blocks[g];
            let aad = aad_bytes_for(&env_for_aad, g);
            SealedGroupInfo {
                name: g.clone(),
                ciphertext_b64: STANDARD.encode(&b.ciphertext),
                field_hashes: b.field_hashes.clone(),
                aad_b64: if aad.is_empty() {
                    String::new()
                } else {
                    STANDARD.encode(&aad)
                },
                keystore_candidates: unusable_keystore_kinds(walk_keystore, g),
            }
        })
        .collect();

    // Entry-style merge (Entry.from_raw): opened group plaintexts in
    // alphabetical group order, last-write-wins on field collision.
    let mut fields: Map<String, Value> = Map::new();
    for body in plaintext.values() {
        if let Value::Object(obj) = body {
            for (k, v) in obj {
                fields.insert(k.clone(), v.clone());
            }
        }
    }
    // Then non-reserved, non-block public extras. Entry.from_raw's
    // basics set adds run_id and message to the nine reserved scalars.
    for (k, v) in &env {
        if ENVELOPE_RESERVED.contains(&k.as_str()) || k == "run_id" || k == "message" {
            continue;
        }
        if blocks.contains_key(k) {
            continue;
        }
        if k == TN_SEALED_KEY {
            // The wire marker must not leak into user fields — a
            // re-seal of entry.fields would trip the reserved-name
            // guard (mirrors seal.py:350-357).
            continue;
        }
        fields.insert(k.clone(), v.clone());
    }
    // Entry.from_raw pops these out of fields into typed slots; the
    // outcome has no such slots, so they are dropped from fields to
    // keep the merge identical.
    fields.remove("run_id");
    fields.remove("message");

    UnsealOutcome {
        envelope: env,
        plaintext,
        valid,
        hidden_groups,
        sealed_blocks,
        fields,
    }
}
