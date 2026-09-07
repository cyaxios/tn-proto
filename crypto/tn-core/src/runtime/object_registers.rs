//! Optional per-service creation and release registers using ordinary TN rows.

use std::path::PathBuf;

use crate::governed::GovernedObject;
use crate::{DeviceKey, Error, Result};

/// Independent, optional metadata registers for an object service.
///
/// Construction only captures paths. A successful [`Self::record`] appends one
/// signed, hash-chained TN row containing the object's identity, action, policy
/// references, purpose, and destination. It never reads the object's plaintext.
/// Each append verifies the existing register while holding its file lock.
#[derive(Debug, Clone, Default)]
pub struct ObjectRegisters {
    creation: Option<PathBuf>,
    release: Option<PathBuf>,
}

impl ObjectRegisters {
    /// Configure each register independently; absent or empty paths disable it.
    pub fn new(creation: Option<PathBuf>, release: Option<PathBuf>) -> Self {
        Self {
            creation: creation.filter(|path| !path.as_os_str().is_empty()),
            release: release.filter(|path| !path.as_os_str().is_empty()),
        }
    }

    /// Capture `TN_OBJECT_CREATION_REGISTER` and `TN_OBJECT_RELEASE_REGISTER`.
    /// Later environment changes do not alter this service's configuration.
    /// Unset and empty variables disable their corresponding registers.
    pub fn from_env() -> Result<Self> {
        Ok(Self::new(
            std::env::var_os("TN_OBJECT_CREATION_REGISTER").map(PathBuf::from),
            std::env::var_os("TN_OBJECT_RELEASE_REGISTER").map(PathBuf::from),
        ))
    }

    /// Append metadata for `create` or `release`, returning whether it was written.
    ///
    /// Disabled actions return `false` without touching the filesystem. An enabled
    /// register requires `fs-locking` and refuses corrupted or incomplete history.
    /// Errors concern registration only; the caller owns the business operation
    /// and any retry or retention of its already-created object.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        device: &DeviceKey,
        action: &str,
        object: &GovernedObject,
        purpose: &str,
        destination: &str,
        policy_refs: &[String],
    ) -> Result<bool> {
        let path = match action {
            "create" => &self.creation,
            "release" => &self.release,
            _ => {
                return Err(Error::InvalidConfig(
                    "object register action must be create or release".into(),
                ));
            }
        };
        let Some(path) = path else { return Ok(false) };
        #[cfg(feature = "fs-locking")]
        {
            locked::append(
                path,
                device,
                action,
                object,
                purpose,
                destination,
                policy_refs,
            )?;
            Ok(true)
        }
        #[cfg(not(feature = "fs-locking"))]
        {
            let _ = (path, device, object, purpose, destination, policy_refs);
            Err(Error::InvalidConfig(
                "object registers require the fs-locking feature".into(),
            ))
        }
    }
}

#[cfg(feature = "fs-locking")]
mod locked {
    use std::collections::BTreeMap;
    use std::fs::{self, File, OpenOptions};
    use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
    use std::path::Path;

    use serde::{Deserialize, Serialize};
    use serde_json::{Map, Value};

    use crate::chain::{compute_row_hash, RowHashInput, ZERO_HASH};
    use crate::envelope::{build_envelope, EnvelopeInput};
    use crate::governed::GovernedObject;
    use crate::sealed_object::verify_sealed;
    use crate::signing::signature_b64;
    use crate::{DeviceKey, Error, Result};

    use super::super::util::current_timestamp;

    // Typed, closed deserialization rejects duplicate or unknown fields and
    // prevents an apparent metadata row from hiding encrypted groups/plaintext.
    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct RegisterRow {
        device_identity: String,
        timestamp: String,
        event_id: String,
        event_type: String,
        level: String,
        sequence: u64,
        prev_hash: String,
        row_hash: String,
        signature: String,
        object_id: String,
        action: String,
        policy_refs: Vec<String>,
        purpose: String,
        destination: String,
    }

    fn malformed(reason: impl Into<String>) -> Error {
        Error::Malformed {
            kind: "object register",
            reason: reason.into(),
        }
    }

    fn event_type(action: &str) -> Result<&'static str> {
        match action {
            "create" => Ok("tn.object.created"),
            "release" => Ok("tn.object.released"),
            _ => Err(malformed("unrecognized object action")),
        }
    }

    fn validate_metadata(
        object_id: &str,
        purpose: &str,
        destination: &str,
        policy_refs: &[String],
    ) -> Result<()> {
        // The old TN hash preimage uses NUL delimiters. Reject that delimiter in
        // its direct string fields; arrays remain typed under the closed schema.
        if [object_id, purpose, destination]
            .into_iter()
            .chain(policy_refs.iter().map(String::as_str))
            .any(|value| value.contains('\0'))
        {
            return Err(malformed("metadata must not contain NUL delimiters"));
        }
        let valid_id = object_id.strip_prefix("sha256:").is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
        if !valid_id {
            return Err(malformed("object_id requires a signed object hash"));
        }
        Ok(())
    }

    fn verified_tips(file: &mut File) -> Result<BTreeMap<String, (u64, String)>> {
        let mut tips: BTreeMap<String, (u64, String)> = BTreeMap::new();
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            // A failed/crashed append cannot become the starting point for a
            // new row, even when its JSON happened to finish before the newline.
            if !line.ends_with('\n') {
                return Err(malformed("incomplete final row; register requires repair"));
            }
            let row: RegisterRow = serde_json::from_str(&line)
                .map_err(|error| malformed(format!("invalid row: {error}")))?;
            if row.event_type != event_type(&row.action)? || row.level != "info" {
                return Err(malformed("row action, event type, or level is invalid"));
            }
            validate_metadata(
                &row.object_id,
                &row.purpose,
                &row.destination,
                &row.policy_refs,
            )?;
            if uuid::Uuid::parse_str(&row.event_id).map_or(true, |id| id.get_version_num() != 4)
                || time::OffsetDateTime::parse(
                    &row.timestamp,
                    &time::format_description::well_known::Rfc3339,
                )
                .is_err()
            {
                return Err(malformed("row timestamp or event identity is invalid"));
            }
            let value = serde_json::to_value(&row)?;
            let envelope = value
                .as_object()
                .expect("RegisterRow serializes as a JSON object");
            let valid = verify_sealed(envelope, &BTreeMap::new());
            if !valid.signature || !valid.row_hash {
                return Err(malformed("row signature or hash verification failed"));
            }
            let (sequence, previous) = next_tip(&tips, &row.event_type)?;
            // The old TN row hash excludes sequence. Check it separately for
            // every row, including genesis, instead of trusting a signed hash.
            if row.sequence != sequence || row.prev_hash != previous {
                return Err(malformed("row sequence or previous hash breaks the chain"));
            }
            tips.insert(row.event_type, (row.sequence, row.row_hash));
        }
        Ok(tips)
    }

    fn next_tip<'a>(
        tips: &'a BTreeMap<String, (u64, String)>,
        event_type: &str,
    ) -> Result<(u64, &'a str)> {
        tips.get(event_type)
            .map_or(Ok((1, ZERO_HASH)), |(sequence, hash)| {
                sequence
                    .checked_add(1)
                    .map(|next| (next, hash.as_str()))
                    .ok_or_else(|| malformed("register sequence exhausted"))
            })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn append(
        path: &Path,
        device: &DeviceKey,
        action: &str,
        object: &GovernedObject,
        purpose: &str,
        destination: &str,
        policy_refs: &[String],
    ) -> Result<()> {
        validate_metadata(object.id(), purpose, destination, policy_refs)?;
        let event_type = event_type(action)?;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        // Each call has its own handle, so the operating-system lock serializes
        // threads as well as processes, including separate service instances.
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        fs4::fs_std::FileExt::lock_exclusive(&file)?;
        // File owns the lock until drop on every success/error path. No cached
        // tail or sequence is trusted across calls or service reopenings.
        let tips = verified_tips(&mut file)?;
        let (sequence, previous) = next_tip(&tips, event_type)?;
        let timestamp = current_timestamp();
        let event_id = uuid::Uuid::new_v4().to_string();
        let public_fields = BTreeMap::from([
            ("object_id".into(), Value::String(object.id().into())),
            ("action".into(), Value::String(action.into())),
            ("policy_refs".into(), serde_json::to_value(policy_refs)?),
            ("purpose".into(), Value::String(purpose.into())),
            ("destination".into(), Value::String(destination.into())),
        ]);
        let row_hash = compute_row_hash(&RowHashInput {
            device_identity: device.did(),
            timestamp: &timestamp,
            event_id: &event_id,
            event_type,
            level: "info",
            prev_hash: previous,
            public_fields: &public_fields,
            groups: &BTreeMap::new(),
        });
        let signature = signature_b64(&device.sign(row_hash.as_bytes()));
        let line = build_envelope(EnvelopeInput {
            device_identity: device.did(),
            timestamp: &timestamp,
            event_id: &event_id,
            event_type,
            level: "info",
            sequence,
            prev_hash: previous,
            row_hash: &row_hash,
            signature_b64: &signature,
            public_fields: public_fields.into_iter().collect::<Map<_, _>>(),
            group_payloads: BTreeMap::new(),
        })?;
        let original_len = file.seek(SeekFrom::End(0))?;
        if let Err(write_error) = file
            .write_all(line.as_bytes())
            .and_then(|()| file.sync_data())
        {
            // Restore the verified prefix after a short write or flush failure.
            // If restoration itself fails, stop and report both errors; a later
            // caller still must validate the entire file before appending.
            if let Err(restore_error) = file.set_len(original_len).and_then(|()| file.sync_data()) {
                return Err(Error::Io(std::io::Error::new(
                    restore_error.kind(),
                    format!("register append failed: {write_error}; restoring prior length failed: {restore_error}"),
                )));
            }
            return Err(Error::Io(write_error));
        }
        Ok(())
    }
}
