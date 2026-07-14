//! Manifest signing and verification.
//!
//! Every `.tnpkg` manifest carries an Ed25519 signature over its own
//! canonical bytes (the manifest minus the signature field — see
//! [`Manifest::signing_bytes`](super::Manifest::signing_bytes)). A production
//! package producer calls [`sign_manifest_with_body`] with its final stored
//! body and device key; [`sign_manifest`] remains the lower-level
//! manifest-only primitive. A receiver runs [`verify_manifest`] against the producer named in
//! [`publisher_identity`](super::Manifest::publisher_identity) before trusting
//! the body.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use super::zip_write::validate_tnpkg_body_name;
use super::{BodyContents, Manifest};
use crate::{Error, Result};

// Multicodec validation lives in the one strict parser
// (`crate::trust::parse_ed25519_did_key`) now. Pin at compile time that the
// prefix this module historically enforced is the prefix the parser enforces,
// so the two can never drift apart silently.
const _: () = assert!(matches!(super::ED25519_MULTICODEC, [0xed, 0x01]));

/// Sign a manifest in place, populating
/// [`manifest_signature_b64`](Manifest::manifest_signature_b64).
///
/// Signs [`Manifest::signing_bytes`] (the canonical form minus the signature)
/// with `sk` and stores the standard-base64 Ed25519 signature back on the
/// manifest. `sk` must be the signing key whose public half is encoded in
/// [`Manifest::publisher_identity`], or the later [`verify_manifest`] will fail.
/// Side effect: mutates `manifest`.
/// For a complete `.tnpkg`, prefer [`sign_manifest_with_body`] so final body
/// bytes are indexed before this signature is computed.
///
/// # Errors
///
/// Returns [`crate::Error`] if [`Manifest::signing_bytes`] fails to
/// canonicalize.
pub fn sign_manifest(manifest: &mut Manifest, sk: &SigningKey) -> Result<()> {
    let bytes = manifest.signing_bytes()?;
    let sig = sk.sign(&bytes);
    manifest.manifest_signature_b64 = Some(B64_STANDARD.encode(sig.to_bytes()));
    Ok(())
}

/// Compute the exact lowercase tagged SHA-256 index for final body bytes.
pub fn compute_body_sha256(body: &BodyContents) -> Result<BTreeMap<String, String>> {
    body.iter()
        .map(|(name, bytes)| {
            validate_tnpkg_body_name(name)?;
            Ok((
                name.clone(),
                format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
            ))
        })
        .collect()
}

/// Populate the body index and invalidate any signature over an older body.
pub fn prepare_manifest_body_index(manifest: &mut Manifest, body: &BodyContents) -> Result<()> {
    manifest.body_sha256 = compute_body_sha256(body)?;
    manifest.body_sha256_present = true;
    manifest.manifest_signature_b64 = None;
    Ok(())
}

/// Index final stored body bytes, then sign the complete manifest domain.
pub fn sign_manifest_with_body(
    manifest: &mut Manifest,
    body: &BodyContents,
    sk: &SigningKey,
) -> Result<()> {
    prepare_manifest_body_index(manifest, body)?;
    sign_manifest(manifest, sk)
}

/// Verify the manifest's exact body member set and lowercase tagged digests.
pub fn verify_manifest_body_index(
    manifest: &Manifest,
    body: &BodyContents,
    require_index: bool,
) -> Result<()> {
    if !manifest.body_sha256_present {
        if require_index {
            return Err(body_digest_error("manifest body_sha256 index is missing"));
        }
        return Ok(());
    }

    for (name, digest) in &manifest.body_sha256 {
        validate_tnpkg_body_name(name)
            .map_err(|_| body_digest_error(&format!("invalid indexed body member {name:?}")))?;
        let hex = digest.strip_prefix("sha256:").unwrap_or_default();
        if hex.len() != 64
            || !hex
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(body_digest_error(&format!(
                "malformed digest for body member {name:?}"
            )));
        }
    }

    let actual = compute_body_sha256(body)
        .map_err(|_| body_digest_error("body member set contains an invalid path"))?;
    if manifest.body_sha256 != actual {
        return Err(body_digest_error("body index mismatch"));
    }
    Ok(())
}

fn body_digest_error(detail: &str) -> Error {
    Error::Malformed {
        kind: "tnpkg body index",
        reason: format!("body_digest_mismatch: {detail}"),
    }
}

/// Verify a manifest's signature against its declared producer.
///
/// Decodes the Ed25519 public key from [`Manifest::publisher_identity`]
/// (`did:key:z…`), decodes the standard-base64
/// [`manifest_signature_b64`](Manifest::manifest_signature_b64), and checks it
/// over [`Manifest::signing_bytes`]. This is the gate
/// [`crate::Runtime::absorb`] runs before trusting a package's body. Pure
/// (reads only the manifest); `Ok(())` means the producer named in the manifest
/// signed exactly these bytes.
///
/// # Errors
///
/// Returns [`crate::Error::Malformed`] when the manifest is unsigned, the
/// `publisher_identity` is not a verifiable Ed25519 `did:key`, the signature is
/// not valid 64-byte base64, or the signature does not verify (tampered
/// manifest).
pub fn verify_manifest(manifest: &Manifest) -> Result<()> {
    let sig_b64 = manifest
        .manifest_signature_b64
        .as_deref()
        .ok_or_else(|| Error::Malformed {
            kind: "tnpkg manifest",
            reason: "manifest is unsigned".into(),
        })?;
    let pub_bytes = did_key_pub(&manifest.publisher_identity)?;
    let vk = VerifyingKey::from_bytes(&pub_bytes).map_err(|e| Error::Malformed {
        kind: "tnpkg manifest pubkey",
        reason: e.to_string(),
    })?;
    let sig_bytes = B64_STANDARD.decode(sig_b64).map_err(|e| Error::Malformed {
        kind: "tnpkg manifest signature",
        reason: e.to_string(),
    })?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed {
            kind: "tnpkg manifest signature",
            reason: "expected 64-byte Ed25519 signature".into(),
        })?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    let msg = manifest.signing_bytes()?;
    vk.verify(&msg, &sig).map_err(|e| Error::Malformed {
        kind: "tnpkg manifest signature",
        reason: format!("verify failed: {e}"),
    })?;
    Ok(())
}

/// Extract the 32-byte Ed25519 public key from a `did:key:z…` identifier.
///
/// Internal helper for [`verify_manifest`], routed through the one strict
/// parser in [`crate::trust::parse_ed25519_did_key`] so package verification
/// and enrollment ceremonies accept exactly the same identifiers. Public
/// callers verify `did:key` signatures through
/// [`crate::DeviceKey::verify_did`] (behind `tn init`) or the strict
/// [`crate::trust`] API, not this function.
pub(crate) fn did_key_pub(did: &str) -> Result<[u8; 32]> {
    crate::trust::parse_ed25519_did_key(did).map_err(|error| Error::Malformed {
        kind: "tnpkg manifest publisher_identity",
        reason: error.detail,
    })
}
