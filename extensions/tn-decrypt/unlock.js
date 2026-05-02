// extensions/tn-decrypt/unlock.js — thin re-export wrapper around the
// SDK's audited EMK module. The actual implementations live at
// ts-sdk/src/core/emk.ts (compiled and vendored into
// ./vendor/sdk-core/emk.js by tools/build-extension.sh).
//
// The extension imports ONLY from ./vendor/sdk-core/ so the directory
// is self-contained: zip extensions/tn-decrypt/, load unpacked from
// anywhere, and it works without the sibling ts-sdk/ tree being present.
// Re-run tools/build-extension.sh after every SDK change to refresh the
// vendored copies.

export {
  bytesToB64,
  b64ToBytes,
  randomBytes as rand,
} from "./vendor/sdk-core/encoding.js";

export {
  importEmk,
  deriveEmkFromPassphrase,
  emkFromPrfOutput,
  makeVerifier,
  checkVerifier,
  wrapKeystoreSecret,
  unwrapKeystoreSecret,
} from "./vendor/sdk-core/emk.js";

// probePrfSupport stays inline — pure feature-detect, no crypto.
export async function probePrfSupport() {
  if (typeof PublicKeyCredential === "undefined") {
    return { supported: false, reason: "no PublicKeyCredential" };
  }
  return { supported: true };
}
