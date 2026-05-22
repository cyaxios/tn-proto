// STATUS: SKETCH. Not yet verified against the Rust-side keystore
// layout in `tn-core/src/storage.rs` — the field names below
// (`local.private` etc.) and the wasm `generateDeviceKey` return shape
// were guessed and need to be confirmed before this file is wired into
// the browser entry. DO NOT EXPORT FROM THE PACKAGE UNTIL VERIFIED.
//
// Internal browser helper — NOT exported from the package.
//
// First-time bootstrap: when `Tn.init()` is called and the configured
// localStorage prefix is empty, this module writes a minimal `tn.yaml`
// plus a freshly-minted device keypair so the subsequent
// `WasmRuntime.initWith` call has everything it needs on disk.
//
// On subsequent `Tn.init()` calls the prefix is non-empty and this
// module is a no-op — the existing ceremony is loaded as-is.
//
// This is the JS equivalent of what `tn.config.create_fresh()` does
// in Python or what `tn init` does at the CLI. It's NOT a public verb;
// the consumer calls `Tn.init()` (same name as Node and Python), this
// runs internally when needed.
//
// Implementation notes:
//   * Uses wasm primitives only (generateDeviceKey, canonicalBytes).
//     No Node deps, no node:fs, no node:path.
//   * Writes through the supplied JsStorageCallbacks adapter — the
//     storage layer decides where things actually persist.
//   * Yaml content mirrors the canonical shape produced by Python's
//     `tn.config.create_fresh()`. If that file changes, this one must
//     follow. Reference:
//       tn_proto/python/tn/config.py::create_fresh
//
// Locked-down surface: every export starts with `_` to signal
// "internal browser-build glue, not consumer API".

import type { JsStorageCallbacks } from "../runtime/storage_node.js";

/** The path inside the storage prefix where the yaml manifest lives. */
export const _YAML_PATH = "tn.yaml";

/** The keystore directory inside the storage prefix. */
const _KEYSTORE_DIR = ".tn/default/keys";

/** The admin-log path inside the storage prefix. */
const _ADMIN_LOG_PATH = ".tn/default/admin/admin.ndjson";

/** The main log path inside the storage prefix. */
const _LOG_PATH = ".tn/default/logs/tn.ndjson";

/**
 * Build the canonical tn.yaml text for a fresh browser-side ceremony.
 *
 * Mirrors Python's `tn.config.create_fresh` field-for-field with one
 * exception: `handlers` omits `file.rotating` and `stdout` (the
 * browser doesn't have either; events flow through wasm to the
 * in-storage log only).
 *
 * @param did - the public DID of the freshly-minted device key
 */
function _buildYaml(did: string): string {
  return [
    "version: 1",
    "ceremony:",
    "  mode: local",
    "  sign: true",
    "  log_level: info",
    `  admin_log_location: ${_ADMIN_LOG_PATH}`,
    "logs:",
    `  path: ${_LOG_PATH}`,
    "keystore:",
    `  path: ${_KEYSTORE_DIR}`,
    "handlers: []",
    "public_fields: []",
    "default_policy: private",
    "fields: {}",
    "groups:",
    "  default:",
    "    policy: private",
    "    cipher: btn",
    "    recipients:",
    `      - did: ${did}`,
    "llm_classifier:",
    "  enabled: false",
    "  provider: ''",
    "  model: ''",
    "",
  ].join("\n");
}

/**
 * Whether storage looks empty (no yaml manifest at the expected path).
 *
 * Cheap synchronous probe; just calls `storage.exists(yaml_path)`.
 */
export function _hasExistingCeremony(storage: JsStorageCallbacks): boolean {
  return storage.exists(_YAML_PATH);
}

/**
 * Initialize a fresh ceremony in `storage`. Idempotent: if a yaml
 * already exists at `_YAML_PATH`, returns early without overwriting.
 *
 * Required `wasm` shape: must expose `generateDeviceKey`. Per the
 * type definitions in pkg-web/tn_wasm.d.ts, the actual return shape
 * is `{ seed, publicKey, did }` — NOT what's typed in the parameter
 * stub below. The parameter stub here is a placeholder pending
 * verification against `crypto/tn-wasm/src/lib.rs::generateDeviceKey`
 * and the keystore-layout contract in `tn-core/src/storage.rs`.
 *
 * @returns the yaml path that should be passed to `WasmRuntime.initWith`
 */
export function _initFreshCeremony(
  storage: JsStorageCallbacks,
  wasm: {
    generateDeviceKey(): {
      device_did: string;
      device_did_private_b64: string;
      device_did_public_b64: string;
    };
  },
): string {
  if (_hasExistingCeremony(storage)) return _YAML_PATH;

  // 1. Mint a fresh device keypair via wasm.
  const kp = wasm.generateDeviceKey();

  // 2. Persist keystore files. Layout matches what `tn init` writes:
  //
  //     <keystore>/local.private          ascii base64 of Ed25519 priv
  //     <keystore>/local.public           ascii base64 of Ed25519 pub
  //     <keystore>/local.did              ascii did:key string
  //
  // The runtime reads these on `WasmRuntime.initWith` to bind its
  // publisher identity.
  const enc = new TextEncoder();
  storage.write(`${_KEYSTORE_DIR}/local.private`, enc.encode(kp.device_did_private_b64));
  storage.write(`${_KEYSTORE_DIR}/local.public`, enc.encode(kp.device_did_public_b64));
  storage.write(`${_KEYSTORE_DIR}/local.did`, enc.encode(kp.device_did));

  // 3. Persist the canonical yaml manifest. WasmRuntime.initWith
  // parses this at init time to discover ciphers, recipients, etc.
  const yaml = _buildYaml(kp.device_did);
  storage.write(_YAML_PATH, enc.encode(yaml));

  return _YAML_PATH;
}
