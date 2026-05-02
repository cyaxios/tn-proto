// extensions/tn-decrypt/unlock.js — thin re-export wrapper around the
// SDK's audited EMK module. The actual implementations live at
// ts-sdk/src/core/emk.ts (compiled to ../../ts-sdk/dist/core/emk.js).
//
// Production Chrome Web Store packaging will vendor ts-sdk/dist/core/
// into ./vendor/sdk-core/ as part of the build script. For dev-install
// (load unpacked from this directory inside the repo), the relative
// path resolves to the built SDK directly.

export {
  bytesToB64,
  b64ToBytes,
  randomBytes as rand,
} from "../../ts-sdk/dist/core/encoding.js";

export {
  importEmk,
  deriveEmkFromPassphrase,
  emkFromPrfOutput,
  makeVerifier,
  checkVerifier,
  wrapKeystoreSecret,
  unwrapKeystoreSecret,
} from "../../ts-sdk/dist/core/emk.js";

// probePrfSupport stays inline — pure feature-detect, no crypto.
export async function probePrfSupport() {
  if (typeof PublicKeyCredential === "undefined") {
    return { supported: false, reason: "no PublicKeyCredential" };
  }
  return { supported: true };
}
