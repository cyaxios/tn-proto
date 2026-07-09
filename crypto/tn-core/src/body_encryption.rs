//! AES-GCM sealed body frame for `.tnpkg` packages.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};

use aes_gcm::aead::Aead as _;
use aes_gcm::aead::Payload;
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::Value;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter};

use crate::{Error, Result};

const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;

/// Cipher-suite identifier in `manifest.state.body_encryption.cipher_suite`.
pub const BODY_CIPHER_SUITE: &str = "aes-256-gcm";

/// Frame identifier in `manifest.state.body_encryption.frame`.
pub const BODY_FRAME: &str = "tn-encrypted-body-v2-zip";

/// Legacy hosted-dashboard frame identifier used by early API-key bundles.
pub const LEGACY_VAULT_BODY_FRAME: &str = "tn-body-encryption-v1";

const LEGACY_VAULT_BODY_AAD: &[u8] = b"tn-vault-body-v1";

/// Body contents keyed by full `body/...` package member name.
pub type BodyPlaintext = BTreeMap<String, Vec<u8>>;

/// Pack sealed body plaintext as a canonical STORED ZIP.
pub fn pack_body_plaintext_zip(body: &BodyPlaintext) -> Result<Vec<u8>> {
    let fixed_time =
        DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0).map_err(|e| Error::Malformed {
            kind: "body plaintext zip",
            reason: e.to_string(),
        })?;
    let opts = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .last_modified_time(fixed_time)
        .unix_permissions(0o644)
        .large_file(false);

    let mut cursor = Cursor::new(Vec::new());
    let mut writer = ZipWriter::new(&mut cursor);
    for (name, data) in body {
        validate_body_name(name)?;
        writer.start_file(name, opts).map_err(zip_err)?;
        writer.write_all(data)?;
    }
    writer.finish().map_err(zip_err)?;
    Ok(cursor.into_inner())
}

/// Encrypt a body map into `body/encrypted.bin` bytes with a caller-supplied nonce.
pub fn encrypt_body_blob_with_nonce(
    body: &BodyPlaintext,
    key: &[u8; 32],
    nonce: &[u8; NONCE_BYTES],
) -> Result<Vec<u8>> {
    let plaintext = pack_body_plaintext_zip(body)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| Error::Malformed {
        kind: "body encryption key",
        reason: e.to_string(),
    })?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(nonce), plaintext.as_ref())
        .map_err(|e| Error::Malformed {
            kind: "body encryption",
            reason: e.to_string(),
        })?;
    let mut out = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt `body/encrypted.bin` bytes back into the original body map.
pub fn decrypt_body_blob(blob: &[u8], key: &[u8; 32]) -> Result<BodyPlaintext> {
    if blob.len() < NONCE_BYTES + TAG_BYTES {
        return Err(Error::Malformed {
            kind: "body encrypted blob",
            reason: "input too short".into(),
        });
    }
    let nonce = &blob[..NONCE_BYTES];
    let ciphertext = &blob[NONCE_BYTES..];
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| Error::Malformed {
        kind: "body encryption key",
        reason: e.to_string(),
    })?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| Error::Malformed {
            kind: "body encrypted blob",
            reason: format!("AES-GCM decrypt failed: {e}"),
        })?;
    if plaintext.len() < 4 || &plaintext[..4] != b"PK\x03\x04" {
        return Err(Error::Malformed {
            kind: "body encrypted blob",
            reason: "plaintext is not a STORED zip".into(),
        });
    }
    unpack_body_plaintext_zip(&plaintext)
}

/// Decrypt the legacy hosted-dashboard body frame used by early API-key bundles.
///
/// This frame stores `body/encrypted.bin` as `ciphertext || tag`, keeps the
/// nonce in `manifest.state.body_encryption.nonce_b64`, and uses the
/// `tn-vault-body-v1` AEAD AAD. New SDK-produced packages should use
/// [`BODY_FRAME`] instead.
pub fn decrypt_legacy_vault_body_blob(
    ciphertext: &[u8],
    key: &[u8; 32],
    nonce_b64: &str,
) -> Result<BodyPlaintext> {
    let nonce = STANDARD.decode(nonce_b64).map_err(|e| Error::Malformed {
        kind: "body encrypted blob",
        reason: format!("nonce_b64 is not valid base64: {e}"),
    })?;
    if nonce.len() != NONCE_BYTES {
        return Err(Error::Malformed {
            kind: "body encrypted blob",
            reason: format!("nonce_b64 decoded to {} bytes; expected 12", nonce.len()),
        });
    }
    if ciphertext.len() < TAG_BYTES {
        return Err(Error::Malformed {
            kind: "body encrypted blob",
            reason: "legacy ciphertext is too short".into(),
        });
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| Error::Malformed {
        kind: "body encryption key",
        reason: e.to_string(),
    })?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: LEGACY_VAULT_BODY_AAD,
            },
        )
        .map_err(|e| Error::Malformed {
            kind: "body encrypted blob",
            reason: format!("legacy AES-GCM decrypt failed: {e}"),
        })?;
    if looks_like_zip(&plaintext) {
        return unpack_body_plaintext_zip(&plaintext);
    }
    if let Some(body) = unpack_legacy_dashboard_json_body(&plaintext)? {
        return Ok(body);
    }
    unpack_legacy_body_plaintext_frame(&plaintext).map_err(|err| Error::Malformed {
        kind: "body encrypted blob",
        reason: format!(
            "{}; decrypted legacy body was not zip or dashboard JSON (len={}, prefix={})",
            err,
            plaintext.len(),
            diagnostic_prefix(&plaintext)
        ),
    })
}

fn unpack_body_plaintext_zip(plaintext: &[u8]) -> Result<BodyPlaintext> {
    let mut zr = ZipArchive::new(Cursor::new(plaintext)).map_err(zip_err)?;
    let mut out = BodyPlaintext::new();
    for i in 0..zr.len() {
        let mut entry = zr.by_index(i).map_err(zip_err)?;
        let name = entry.name().to_string();
        validate_body_name(&name)?;
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        out.insert(name, buf);
    }
    Ok(out)
}

fn looks_like_zip(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && (&bytes[..4] == b"PK\x03\x04"
            || &bytes[..4] == b"PK\x05\x06"
            || &bytes[..4] == b"PK\x07\x08")
}

fn unpack_legacy_body_plaintext_frame(plaintext: &[u8]) -> Result<BodyPlaintext> {
    if plaintext.len() < 4 {
        return Err(Error::Malformed {
            kind: "body encrypted blob",
            reason: "legacy plaintext too short for any known format".into(),
        });
    }

    let mut pos = 0usize;
    let count = read_u32_be(plaintext, &mut pos)? as usize;
    let mut out = BodyPlaintext::new();
    for _ in 0..count {
        let name_len = read_u32_be(plaintext, &mut pos)? as usize;
        if name_len == 0 || name_len > 1024 || pos + name_len > plaintext.len() {
            return Err(Error::Malformed {
                kind: "body encrypted blob",
                reason: format!("legacy member name length {name_len} is invalid"),
            });
        }
        let name =
            std::str::from_utf8(&plaintext[pos..pos + name_len]).map_err(|e| Error::Malformed {
                kind: "body encrypted blob",
                reason: format!("legacy member name is not utf-8: {e}"),
            })?;
        validate_body_name(name)?;
        pos += name_len;

        let data_len = read_u32_be(plaintext, &mut pos)? as usize;
        if pos + data_len > plaintext.len() {
            return Err(Error::Malformed {
                kind: "body encrypted blob",
                reason: format!("legacy member {name:?} data length {data_len} exceeds frame"),
            });
        }
        out.insert(name.to_string(), plaintext[pos..pos + data_len].to_vec());
        pos += data_len;
    }

    if pos != plaintext.len() {
        return Err(Error::Malformed {
            kind: "body encrypted blob",
            reason: "legacy plaintext has trailing bytes".into(),
        });
    }
    Ok(out)
}

fn unpack_legacy_dashboard_json_body(plaintext: &[u8]) -> Result<Option<BodyPlaintext>> {
    let trimmed = plaintext
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map(|pos| &plaintext[pos..])
        .unwrap_or(plaintext);
    if !trimmed.starts_with(b"{") {
        return Ok(None);
    }

    let doc: Value = serde_json::from_slice(plaintext).map_err(|e| Error::Malformed {
        kind: "body encrypted blob",
        reason: format!("legacy dashboard JSON body is invalid: {e}"),
    })?;
    let Some(obj) = doc.as_object() else {
        return Err(Error::Malformed {
            kind: "body encrypted blob",
            reason: "legacy dashboard JSON body is not an object".into(),
        });
    };
    let Some(files) = obj.get("files").and_then(Value::as_object) else {
        return Err(Error::Malformed {
            kind: "body encrypted blob",
            reason: "legacy dashboard JSON body is missing files object".into(),
        });
    };

    let mut out = BodyPlaintext::new();
    if let Some(yaml) = obj.get("yaml").and_then(Value::as_str) {
        out.insert("body/tn.yaml".into(), yaml.as_bytes().to_vec());
    }
    for (name, value) in files {
        let Some(encoded) = value.as_str() else {
            return Err(Error::Malformed {
                kind: "body encrypted blob",
                reason: format!("legacy dashboard file {name:?} is not a base64 string"),
            });
        };
        let member = if name.starts_with("body/") {
            name.clone()
        } else {
            format!("body/{name}")
        };
        validate_body_name(&member)?;
        let data = decode_legacy_base64(encoded).map_err(|e| Error::Malformed {
            kind: "body encrypted blob",
            reason: format!("legacy dashboard file {name:?} is not valid base64: {e}"),
        })?;
        out.insert(member, data);
    }

    Ok(Some(out))
}

fn decode_legacy_base64(encoded: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    let mut normalized = encoded.replace('-', "+").replace('_', "/");
    let padding = (4 - normalized.len() % 4) % 4;
    normalized.extend(std::iter::repeat('=').take(padding));
    STANDARD.decode(normalized)
}

fn diagnostic_prefix(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, byte) in bytes.iter().take(12).enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{byte:02x}"));
    }
    if bytes.len() > 12 {
        out.push_str(" ...");
    }
    out
}

fn read_u32_be(bytes: &[u8], pos: &mut usize) -> Result<u32> {
    if *pos + 4 > bytes.len() {
        return Err(Error::Malformed {
            kind: "body encrypted blob",
            reason: "legacy plaintext ended while reading uint32".into(),
        });
    }
    let value = u32::from_be_bytes(
        bytes[*pos..*pos + 4]
            .try_into()
            .expect("slice length checked above"),
    );
    *pos += 4;
    Ok(value)
}

fn validate_body_name(name: &str) -> Result<()> {
    if !name.starts_with("body/") || name == "body/" {
        return Err(Error::Malformed {
            kind: "body plaintext zip",
            reason: format!("invalid package member {name:?}; expected body/..."),
        });
    }
    if name.starts_with('/')
        || name.contains('\\')
        || name
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::Malformed {
            kind: "body plaintext zip",
            reason: format!(
                "invalid package member {name:?}; only POSIX relative body paths are allowed"
            ),
        });
    }
    Ok(())
}

fn zip_err(e: zip::result::ZipError) -> Error {
    Error::Malformed {
        kind: "body plaintext zip",
        reason: e.to_string(),
    }
}
