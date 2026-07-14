use std::fs;
use std::path::{Path, PathBuf};

const MAX_FILE_LINES: usize = 609;
const TARGET_FUNCTION_LINES: usize = 50;
const ABSOLUTE_FUNCTION_LINES: usize = 200;

struct FunctionException {
    path: &'static str,
    symbol: &'static str,
    reason: &'static str,
}

const FUNCTION_EXCEPTIONS: &[FunctionException] = &[];

#[test]
fn production_read_sources_stay_bounded() {
    let root = workspace_root();
    let files = production_read_sources(&root);
    assert!(!files.is_empty(), "no production read sources found");

    let mut failures = Vec::new();
    for path in files {
        inspect_source(&root, &path, &mut failures);
    }
    inspect_sdk_read_extraction(&root, &mut failures);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn inspect_sdk_read_extraction(root: &Path, failures: &mut Vec<String>) {
    let read_path = root.join("rust-sdk/src/tn/read.rs");
    if !read_path.is_file() {
        failures.push("rust-sdk/src/tn/read.rs: dedicated SDK read module is missing".into());
    }
    let tn_path = root.join("rust-sdk/src/tn.rs");
    let tn_source = fs::read_to_string(tn_path).expect("read SDK tn source");
    if tn_source.contains("pub fn read(&self") {
        failures.push("rust-sdk/src/tn.rs: read implementation must live in tn/read.rs".into());
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn production_read_sources(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_read_module(root.join("crypto/tn-core/src/runtime/read.rs"), &mut files);
    collect_read_module(root.join("crypto/tn-core/src/runtime/read"), &mut files);
    collect_read_module(
        root.join("crypto/tn-core/src/read_as_recipient.rs"),
        &mut files,
    );
    collect_read_module(root.join("rust-sdk/src/tn/read.rs"), &mut files);
    collect_read_module(root.join("rust-sdk/src/tn/read"), &mut files);
    collect_read_module(root.join("rust-sdk/src/read_trust.rs"), &mut files);
    collect_read_module(root.join("rust-sdk/src/security_warning.rs"), &mut files);
    collect_read_module(root.join("rust-sdk/src/watch.rs"), &mut files);
    files.sort();
    files.dedup();
    files
}

fn collect_read_module(path: PathBuf, files: &mut Vec<PathBuf>) {
    if path.is_file() {
        files.push(path);
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        if child.is_dir() {
            collect_read_module(child, files);
        } else if child.extension().and_then(|value| value.to_str()) == Some("rs") {
            files.push(child);
        }
    }
}

fn inspect_source(root: &Path, path: &Path, failures: &mut Vec<String>) {
    let source = fs::read_to_string(path).expect("read production source");
    let relative = relative_path(root, path);
    let file_lines = source.lines().count();
    if file_lines > MAX_FILE_LINES {
        failures.push(format!(
            "{relative}: {file_lines} lines exceeds the {MAX_FILE_LINES}-line production limit"
        ));
    }

    for function in function_lengths(&source) {
        inspect_function(&relative, &function, failures);
    }
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn inspect_function(relative: &str, function: &FunctionLength, failures: &mut Vec<String>) {
    if function.lines > ABSOLUTE_FUNCTION_LINES {
        failures.push(format!(
            "{relative}:{} {} is {} lines; absolute maximum is {ABSOLUTE_FUNCTION_LINES}",
            function.start_line, function.name, function.lines
        ));
        return;
    }
    if function.lines <= TARGET_FUNCTION_LINES {
        return;
    }
    let exception = FUNCTION_EXCEPTIONS
        .iter()
        .find(|item| item.path == relative && item.symbol == function.name);
    match exception {
        Some(item) if !item.reason.trim().is_empty() => {}
        _ => failures.push(format!(
            "{relative}:{} {} is {} lines; target is {TARGET_FUNCTION_LINES} and no named reason exists",
            function.start_line, function.name, function.lines
        )),
    }
}

struct FunctionLength {
    name: String,
    start_line: usize,
    lines: usize,
}

fn function_lengths(source: &str) -> Vec<FunctionLength> {
    let code = sanitize_rust(source);
    let bytes = code.as_bytes();
    let mut functions = Vec::new();
    let mut cursor = 0;
    while let Some(fn_at) = find_token(bytes, cursor, b"fn") {
        let Some((name, after_name)) = function_name(bytes, fn_at + 2) else {
            cursor = fn_at + 2;
            continue;
        };
        let Some(body_start) = bytes[after_name..]
            .iter()
            .position(|byte| *byte == b'{')
            .map(|offset| after_name + offset)
        else {
            break;
        };
        let Some(body_end) = matching_brace(bytes, body_start) else {
            cursor = body_start + 1;
            continue;
        };
        let start_line = line_number(bytes, fn_at);
        let end_line = line_number(bytes, body_end);
        functions.push(FunctionLength {
            name,
            start_line,
            lines: end_line - start_line + 1,
        });
        cursor = body_end + 1;
    }
    functions
}

fn find_token(bytes: &[u8], mut cursor: usize, token: &[u8]) -> Option<usize> {
    while cursor + token.len() <= bytes.len() {
        if &bytes[cursor..cursor + token.len()] == token
            && token_starts_at_boundary(bytes, cursor)
            && token_ends_at_boundary(bytes, cursor + token.len())
        {
            return Some(cursor);
        }
        cursor += 1;
    }
    None
}

fn token_starts_at_boundary(bytes: &[u8], at: usize) -> bool {
    at == 0 || !is_identifier_byte(bytes[at - 1])
}

fn token_ends_at_boundary(bytes: &[u8], at: usize) -> bool {
    at == bytes.len() || !is_identifier_byte(bytes[at])
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn function_name(bytes: &[u8], mut cursor: usize) -> Option<(String, usize)> {
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    let start = cursor;
    while bytes
        .get(cursor)
        .is_some_and(|byte| is_identifier_byte(*byte))
    {
        cursor += 1;
    }
    (cursor > start).then(|| {
        (
            String::from_utf8_lossy(&bytes[start..cursor]).into_owned(),
            cursor,
        )
    })
}

fn matching_brace(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, byte) in bytes[start..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(start + offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn line_number(bytes: &[u8], at: usize) -> usize {
    bytes[..at].iter().filter(|byte| **byte == b'\n').count() + 1
}

fn sanitize_rust(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut clean = bytes.to_vec();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor..].starts_with(b"//") {
            cursor = mask_line_comment(bytes, &mut clean, cursor);
        } else if bytes[cursor..].starts_with(b"/*") {
            cursor = mask_block_comment(bytes, &mut clean, cursor);
        } else if let Some((content_start, hashes)) = raw_string_start(bytes, cursor) {
            cursor = mask_raw_string(bytes, &mut clean, cursor, content_start, hashes);
        } else if bytes[cursor] == b'"' {
            cursor = mask_quoted(bytes, &mut clean, cursor, b'"');
        } else if bytes[cursor] == b'\'' && is_char_literal(bytes, cursor) {
            cursor = mask_quoted(bytes, &mut clean, cursor, b'\'');
        } else {
            cursor += 1;
        }
    }
    String::from_utf8(clean).expect("sanitized source remains utf-8")
}

fn mask_line_comment(bytes: &[u8], clean: &mut [u8], mut cursor: usize) -> usize {
    while cursor < bytes.len() && bytes[cursor] != b'\n' {
        clean[cursor] = b' ';
        cursor += 1;
    }
    cursor
}

fn mask_block_comment(bytes: &[u8], clean: &mut [u8], mut cursor: usize) -> usize {
    let mut depth = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor..].starts_with(b"/*") {
            depth += 1;
            mask_non_newline(clean, cursor, 2);
            cursor += 2;
        } else if bytes[cursor..].starts_with(b"*/") {
            depth = depth.saturating_sub(1);
            mask_non_newline(clean, cursor, 2);
            cursor += 2;
            if depth == 0 {
                break;
            }
        } else {
            mask_non_newline(clean, cursor, 1);
            cursor += 1;
        }
    }
    cursor
}

fn raw_string_start(bytes: &[u8], cursor: usize) -> Option<(usize, usize)> {
    if bytes.get(cursor) != Some(&b'r') {
        return None;
    }
    let mut next = cursor + 1;
    while bytes.get(next) == Some(&b'#') {
        next += 1;
    }
    (bytes.get(next) == Some(&b'"')).then_some((next + 1, next - cursor - 1))
}

fn mask_raw_string(
    bytes: &[u8],
    clean: &mut [u8],
    start: usize,
    content_start: usize,
    hashes: usize,
) -> usize {
    let mut cursor = content_start;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"'
            && bytes.get(cursor + 1..cursor + 1 + hashes) == Some(&vec![b'#'; hashes])
        {
            let end = cursor + 1 + hashes;
            mask_range(clean, start, end);
            return end;
        }
        cursor += 1;
    }
    mask_range(clean, start, bytes.len());
    bytes.len()
}

fn is_char_literal(bytes: &[u8], cursor: usize) -> bool {
    let mut next = cursor + 1;
    if bytes.get(next) == Some(&b'\\') {
        next += 2;
    } else {
        next += 1;
    }
    bytes.get(next) == Some(&b'\'')
}

fn mask_quoted(bytes: &[u8], clean: &mut [u8], start: usize, quote: u8) -> usize {
    let mut cursor = start + 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\\' {
            cursor = (cursor + 2).min(bytes.len());
        } else if bytes[cursor] == quote {
            cursor += 1;
            break;
        } else {
            cursor += 1;
        }
    }
    mask_range(clean, start, cursor);
    cursor
}

fn mask_range(clean: &mut [u8], start: usize, end: usize) {
    for cursor in start..end {
        mask_non_newline(clean, cursor, 1);
    }
}

fn mask_non_newline(clean: &mut [u8], start: usize, len: usize) {
    for byte in clean.iter_mut().skip(start).take(len) {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}
