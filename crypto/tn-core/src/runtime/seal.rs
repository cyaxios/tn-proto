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

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use uuid::Uuid;

use crate::chain::{compute_row_hash, RowHashInput};
use crate::envelope::{build_envelope, EnvelopeInput};
use crate::sealed_object::{
    reject_fragile_public, SealedObjectLine, SEALED_RECEIPT_EVENT, TN_SEALED_KEY,
};
use crate::signing::signature_b64;
use crate::{Error, Result};

use super::util::{current_timestamp, validate_event_type};
use super::Runtime;

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
}
