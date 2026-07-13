use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read as _};
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::{Error, Result};

use super::super::{
    CursorKind, ReadContext, ReadCursorV1, ReadEntry, ReadReport, ReadTrustPolicy, Runtime,
    SourceCursorV1, ValidFlags, VerifyMode,
};
use super::decrypt::{evaluate_prepared_record, EvaluatedRecord, GroupDecryptors};
use super::record::{invalid_record, prepare_record, seed_chain_from_line};

const MAX_POLICY_LINE_BYTES: usize = 8 * 1024 * 1024;

/// Hash a canonical NUL-delimited source descriptor into its stable ID.
pub fn canonical_source_id(descriptor: &[u8]) -> String {
    format!("source:sha256:{}", hex::encode(Sha256::digest(descriptor)))
}

/// Build the stable source ID for an already-joined file path.
pub fn canonical_file_source_id(path: &str) -> String {
    let normalized = normalize_file_source_path(path);
    let mut descriptor = b"file\0".to_vec();
    descriptor.extend_from_slice(normalized.as_bytes());
    canonical_source_id(&descriptor)
}

fn normalize_file_source_path(path: &str) -> String {
    let slashed = path.replace('\\', "/");
    let slashed = slashed.strip_prefix("//?/").unwrap_or(&slashed);
    let (prefix, remainder) = path_prefix(slashed);
    let mut components = Vec::new();
    for component in remainder.split('/') {
        match component {
            ".." if components.last().is_some_and(|last| *last != "..") => {
                components.pop();
            }
            ".." if prefix.is_empty() => components.push(component),
            "" | "." | ".." => {}
            _ => components.push(component),
        }
    }
    format!("{prefix}{}", components.join("/"))
}

fn path_prefix(path: &str) -> (String, &str) {
    if path.len() >= 3
        && path.as_bytes()[0].is_ascii_alphabetic()
        && path.as_bytes()[1] == b':'
        && path.as_bytes()[2] == b'/'
    {
        return (format!("{}:/", path[..1].to_ascii_lowercase()), &path[3..]);
    }
    if let Some(remainder) = path.strip_prefix("//") {
        return ("//".into(), remainder);
    }
    if let Some(remainder) = path.strip_prefix('/') {
        return ("/".into(), remainder);
    }
    (String::new(), path)
}

impl Runtime {
    pub(super) fn scan_file_with_policy(
        &self,
        path: &Path,
        policy: &ReadTrustPolicy,
        context: &ReadContext,
        cursor: Option<&ReadCursorV1>,
    ) -> Result<ReadReport<(ReadEntry, ValidFlags)>> {
        let decryptors = GroupDecryptors::from_runtime(self);
        scan_file_with_decryptors(self, path, policy, context, cursor, &decryptors)
    }

    pub(super) fn read_context_for_path(
        &self,
        path: &Path,
        required_group: Option<String>,
    ) -> ReadContext {
        ReadContext {
            active: true,
            local_log: paths_equivalent(path, &self.log_path),
            detached: false,
            writable: true,
            profile_sign: Some(self.cfg.ceremony.sign),
            profile_chain: Some(self.cfg.ceremony.chain),
            local_device_did: Some(self.device.did().to_owned()),
            required_group,
        }
    }

    pub(super) fn resolve_read_source_path(&self, requested: Option<&Path>) -> PathBuf {
        let path = requested.map_or_else(
            || self.log_path.clone(),
            |path| {
                let directory = self.yaml_path.parent().unwrap_or_else(|| Path::new("."));
                crate::pathutil::resolve(directory, path)
            },
        );
        lexical_normalize(&path)
    }
}

pub(super) fn scan_file_with_decryptors(
    runtime: &Runtime,
    path: &Path,
    policy: &ReadTrustPolicy,
    context: &ReadContext,
    cursor: Option<&ReadCursorV1>,
    decryptors: &GroupDecryptors,
) -> Result<ReadReport<(ReadEntry, ValidFlags)>> {
    let policy = policy.resolve(context)?;
    let source_id = file_source_id(path)?;
    let (next_cursor, start) = file_cursor_start(cursor, &source_id)?;
    if !runtime.storage.exists(path) {
        return Ok(empty_file_read_report(source_id, next_cursor, start));
    }
    let snapshot = open_storage_read_snapshot(runtime.storage.as_ref(), path)?;
    validate_cursor_start(start, snapshot.len)?;
    let reader = BufReader::new(snapshot.reader.take(snapshot.len));
    let state = scan_snapshot(runtime, reader, start, &policy, context, decryptors)?;
    state.finish(source_id, next_cursor, snapshot.len)
}

fn validate_cursor_start(start: u64, snapshot_len: u64) -> Result<()> {
    if start <= snapshot_len {
        return Ok(());
    }
    Err(Error::InvalidConfig(format!(
        "byte-offset cursor {start} exceeds source length {snapshot_len}"
    )))
}

struct ScanState {
    entries: Vec<(ReadEntry, ValidFlags)>,
    scanned: usize,
    skipped: usize,
    offset: u64,
    previous_hashes: HashMap<String, String>,
    line: Vec<u8>,
}

impl ScanState {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            scanned: 0,
            skipped: 0,
            offset: 0,
            previous_hashes: HashMap::new(),
            line: Vec::new(),
        }
    }

    fn advance(&mut self, physical_len: u64) -> Result<(u64, u64)> {
        let start = self.offset;
        self.offset = self
            .offset
            .checked_add(physical_len)
            .ok_or_else(|| Error::InvalidConfig("read source byte offset overflowed u64".into()))?;
        Ok((start, self.offset))
    }

    fn trim_line_end(&mut self) {
        while self
            .line
            .last()
            .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
        {
            self.line.pop();
        }
    }

    fn finish(
        self,
        source_id: String,
        mut cursor: ReadCursorV1,
        snapshot_len: u64,
    ) -> Result<ReadReport<(ReadEntry, ValidFlags)>> {
        if self.offset != snapshot_len {
            return Err(Error::Malformed {
                kind: "log file",
                reason: "read source ended before its captured snapshot length".into(),
            });
        }
        insert_source_cursor(&mut cursor, source_id, snapshot_len);
        Ok(ReadReport {
            yielded: self.entries.len(),
            entries: self.entries,
            scanned: self.scanned,
            skipped: self.skipped,
            cursor,
        })
    }
}

fn scan_snapshot<R: BufRead>(
    runtime: &Runtime,
    mut reader: R,
    start: u64,
    policy: &ReadTrustPolicy,
    context: &ReadContext,
    decryptors: &GroupDecryptors,
) -> Result<ScanState> {
    let inputs = ScanInputs {
        runtime,
        policy,
        context,
        decryptors,
        cursor_start: start,
    };
    let mut state = ScanState::new();
    while let Some(meta) = read_bounded_line(&mut reader, &mut state.line).map_err(Error::Io)? {
        process_line(&mut state, meta, &inputs)?;
    }
    Ok(state)
}

struct ScanInputs<'a> {
    runtime: &'a Runtime,
    policy: &'a ReadTrustPolicy,
    context: &'a ReadContext,
    decryptors: &'a GroupDecryptors,
    cursor_start: u64,
}

fn process_line(state: &mut ScanState, meta: BoundedLine, inputs: &ScanInputs<'_>) -> Result<()> {
    let (line_start, line_end) = state.advance(meta.physical_len)?;
    state.trim_line_end();
    if !meta.overflowed && state.line.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    let line = (!meta.overflowed)
        .then(|| std::str::from_utf8(&state.line).ok())
        .flatten();
    if line_end <= inputs.cursor_start {
        if let Some(line) = line {
            seed_chain_from_line(line, &mut state.previous_hashes);
        }
        return Ok(());
    }
    validate_record_boundary(inputs.cursor_start, line_start)?;
    state.scanned += 1;
    let prepared = line.map_or_else(
        || invalid_record(serde_json::json!({"event_type": "<parse-error>"})),
        |value| prepare_record(value, &mut state.previous_hashes),
    );
    let evaluated =
        evaluate_prepared_record(prepared, inputs.decryptors, inputs.policy, inputs.context)?;
    handle_evaluated(
        inputs.runtime,
        state,
        evaluated,
        inputs.policy,
        inputs.context,
    )
}

fn validate_record_boundary(cursor_start: u64, line_start: u64) -> Result<()> {
    if cursor_start <= line_start {
        return Ok(());
    }
    Err(Error::InvalidConfig(
        "byte-offset cursor must point to a record boundary".into(),
    ))
}

fn handle_evaluated(
    runtime: &Runtime,
    state: &mut ScanState,
    evaluated: EvaluatedRecord,
    policy: &ReadTrustPolicy,
    context: &ReadContext,
) -> Result<()> {
    match evaluated {
        EvaluatedRecord::Accepted(entry, validity) => state.entries.push((entry, validity)),
        EvaluatedRecord::Rejected(entry, decision) => {
            state.skipped += 1;
            if policy.verify == VerifyMode::Raise {
                return Err(super::read_rejection_error(&entry, &decision));
            }
            if policy.verify == VerifyMode::Skip && context.writable {
                super::emit_skip_event_best_effort(runtime, &entry, &decision.reasons);
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) struct BoundedLine {
    pub(super) physical_len: u64,
    pub(super) overflowed: bool,
}

pub(super) fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
) -> std::io::Result<Option<BoundedLine>> {
    buffer.clear();
    let mut physical_len = 0u64;
    let mut overflowed = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(eof_line(physical_len, overflowed));
        }
        let chunk_len = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        let line_ended = available[chunk_len - 1] == b'\n';
        retain_bounded_chunk(buffer, available, chunk_len, &mut overflowed);
        physical_len = add_physical_len(physical_len, chunk_len)?;
        reader.consume(chunk_len);
        if line_ended {
            return Ok(Some(BoundedLine {
                physical_len,
                overflowed,
            }));
        }
    }
}

fn eof_line(physical_len: u64, overflowed: bool) -> Option<BoundedLine> {
    (physical_len != 0).then_some(BoundedLine {
        physical_len,
        overflowed,
    })
}

fn retain_bounded_chunk(
    buffer: &mut Vec<u8>,
    available: &[u8],
    chunk_len: usize,
    overflowed: &mut bool,
) {
    let remaining = MAX_POLICY_LINE_BYTES.saturating_sub(buffer.len());
    let retained = remaining.min(chunk_len);
    buffer.extend_from_slice(&available[..retained]);
    *overflowed |= retained < chunk_len;
}

fn add_physical_len(current: u64, chunk_len: usize) -> std::io::Result<u64> {
    let increment = u64::try_from(chunk_len)
        .map_err(|_| std::io::Error::other("line byte count does not fit u64"))?;
    current
        .checked_add(increment)
        .ok_or_else(|| std::io::Error::other("line byte count overflowed u64"))
}

pub(super) fn open_storage_read_snapshot(
    storage: &dyn crate::storage::Storage,
    path: &Path,
) -> Result<crate::storage::StorageReadSnapshot> {
    if let Some(snapshot) = storage.open_read_snapshot(path).map_err(Error::Io)? {
        return Ok(snapshot);
    }
    let bytes = storage.read_bytes(path).map_err(Error::Io)?;
    let len = u64::try_from(bytes.len()).map_err(|_| {
        Error::InvalidConfig("read source is too large for a u64 byte cursor".into())
    })?;
    Ok(crate::storage::StorageReadSnapshot {
        reader: Box::new(std::io::Cursor::new(bytes)),
        len,
    })
}

fn empty_file_read_report(
    source_id: String,
    mut cursor: ReadCursorV1,
    position: u64,
) -> ReadReport<(ReadEntry, ValidFlags)> {
    insert_source_cursor(&mut cursor, source_id, position);
    ReadReport {
        entries: Vec::new(),
        scanned: 0,
        yielded: 0,
        skipped: 0,
        cursor,
    }
}

fn insert_source_cursor(cursor: &mut ReadCursorV1, source_id: String, value: u64) {
    cursor.sources.insert(
        source_id,
        SourceCursorV1 {
            kind: CursorKind::ByteOffset,
            value: value.to_string(),
        },
    );
}

fn file_cursor_start(
    cursor: Option<&ReadCursorV1>,
    source_id: &str,
) -> Result<(ReadCursorV1, u64)> {
    let next = cursor.cloned().unwrap_or_default();
    if next.version != 1 {
        return Err(Error::InvalidConfig(format!(
            "unsupported read cursor version {}; expected 1",
            next.version
        )));
    }
    let start = match next.sources.get(source_id) {
        None => 0,
        Some(source) if source.kind == CursorKind::ByteOffset => source
            .value
            .parse::<u64>()
            .map_err(|_| Error::InvalidConfig("byte-offset cursor must be a u64 string".into()))?,
        Some(_) => {
            return Err(Error::InvalidConfig(
                "file source cursor must use kind=byte_offset".into(),
            ));
        }
    };
    Ok((next, start))
}

/// Build the stable source ID for a file path after making it absolute and
/// applying the same lexical normalization used by the read scanner.
pub fn file_source_id(path: &Path) -> Result<String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(Error::Io)?.join(path)
    };
    let normalized = lexical_normalize(&absolute);
    let rendered = normalized
        .to_str()
        .ok_or_else(|| Error::InvalidConfig("read source path must be UTF-8".into()))?;
    Ok(canonical_file_source_id(rendered))
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push(component.as_os_str());
                }
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn paths_equivalent(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    let absolute = |path: &Path| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_or_else(|_| path.to_path_buf(), |directory| directory.join(path))
        }
    };
    lexical_normalize(&absolute(left)) == lexical_normalize(&absolute(right))
}
