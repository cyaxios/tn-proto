//! AES-GCM sealed body frame for `.tnpkg` packages.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};

use aes_gcm::aead::Aead as _;
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter};

use crate::{Error, Result};

const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;

/// Cipher-suite identifier in `manifest.state.body_encryption.cipher_suite`.
pub const BODY_CIPHER_SUITE: &str = "aes-256-gcm";

/// Frame identifier in `manifest.state.body_encryption.frame`.
pub const BODY_FRAME: &str = "tn-encrypted-body-v2-zip";

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
