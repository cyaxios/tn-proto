//! Manifest signing and verification.
//!
//! Every `.tnpkg` manifest carries an Ed25519 signature over its own
//! canonical bytes (the manifest minus the signature field — see
//! [`Manifest::signing_bytes`](super::Manifest::signing_bytes)). The producer
//! calls [`sign_manifest`] with its device key; a receiver runs
//! [`verify_manifest`] against the producer named in
//! [`publisher_identity`](super::Manifest::publisher_identity) before trusting
//! the body.

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

use super::{Manifest, ED25519_MULTICODEC};
use crate::{Error, Result};

/// Sign a manifest in place, populating
/// [`manifest_signature_b64`](Manifest::manifest_signature_b64).
///
/// Signs [`Manifest::signing_bytes`] (the canonical form minus the signature)
/// with `sk` and stores the standard-base64 Ed25519 signature back on the
/// manifest. `sk` must be the signing key whose public half is encoded in
/// [`Manifest::publisher_identity`], or the later [`verify_manifest`] will fail.
/// Side effect: mutates `manifest`.
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
/// Internal helper for [`verify_manifest`]. Public callers verify `did:key`
/// signatures through [`crate::DeviceKey::verify_did`] (behind `tn init`),
/// not this function.
pub(crate) fn did_key_pub(did: &str) -> Result<[u8; 32]> {
    let rest = did
        .strip_prefix("did:key:z")
        .ok_or_else(|| Error::Malformed {
            kind: "tnpkg manifest publisher_identity",
            reason: format!("unsupported DID form: {did:?}"),
        })?;
    let multi = bs58::decode(rest)
        .into_vec()
        .map_err(|e| Error::Malformed {
            kind: "tnpkg manifest publisher_identity",
            reason: e.to_string(),
        })?;
    if multi.len() < 2 || multi[..2] != ED25519_MULTICODEC {
        return Err(Error::Malformed {
            kind: "tnpkg manifest publisher_identity",
            reason: "manifest signing key must be Ed25519 (multicodec 0xed)".into(),
        });
    }
    let pub_bytes: [u8; 32] = multi[2..].try_into().map_err(|_| Error::Malformed {
        kind: "tnpkg manifest publisher_identity",
        reason: "DID pub bytes are not 32-byte Ed25519".into(),
    })?;
    Ok(pub_bytes)
}
