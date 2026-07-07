/**
 * Browser-side fresh-ceremony bootstrap.
 *
 * JS port of `createFreshCeremony` in `src/runtime/node_runtime.ts`.
 * Same output (byte-identical yaml + keystore layout) so the wasm
 * runtime reads what we write here exactly the way it would read what
 * the Node or Python sides produce. The only differences are
 * mechanical:
 *
 * - Random bytes come from `crypto.getRandomValues` (browser- and
 *   worker-safe) instead of Node's `crypto.randomBytes`.
 * - Disk writes go through a {@link JsStorageCallbacks} adapter
 *   instead of `node:fs`. The default is the localStorage one; tests
 *   pass the in-memory adapter.
 * - Paths are opaque storage keys, not filesystem paths — no
 *   `dirname` / `relative` step. The yaml's `keystore.path` is just
 *   the directory key the wasm runtime will use to look up
 *   `local.private` etc.
 * - No `Buffer`. Hex and UTF-8 are pure JS.
 *
 * The yaml literal mirrors `createFreshCeremony`'s byte-for-byte —
 * public-fields list, group block, `llm_classifier` defaults — so a
 * yaml minted in the browser can be diffed against a Python-minted one
 * and only the ceremony id + DID differ.
 *
 * @packageDocumentation
 */

import { DeviceKey } from "../core/signing.js";
import { BtnPublisher } from "../raw.js";
import type { JsStorageCallbacks } from "../runtime/storage_node.js";

/**
 * Knobs for {@link createFreshCeremony}. All optional — defaults match
 * the Node side's "stem == yamlBasename without extension" convention.
 *
 * @public
 */
export interface CreateFreshOptions {
  /**
   * Storage prefix that holds the new ceremony. All keystore + log +
   * admin paths inside the yaml resolve relative to this. The yaml
   * itself is written at `<root>/tn.yaml`. Default: `"/v"`.
   *
   * The leading `/` is conventional — it mirrors the in-memory adapter
   * docs and keeps "stem" semantics aligned with the Node side. The
   * actual localStorage keys are prefixed further by the adapter (e.g.
   * `tn//v/tn.yaml`).
   */
  root?: string;
  /**
   * Yaml file basename, without extension. Used as the `<stem>` segment
   * in the default keystore / log / admin paths the yaml records.
   * Default: `"tn"` (yielding paths like `./.tn/tn/keys/...`, matching
   * `createFreshCeremony` in node_runtime.ts).
   */
  stem?: string;
  /**
   * Optional 32-byte Ed25519 seed to bind the ceremony to. If omitted, a
   * fresh random seed is minted via `crypto.getRandomValues`. Used by
   * the `identity_seed` bootstrap path the Node side documents — caller
   * already has the absorbed device key and wants the new ceremony to
   * carry that DID.
   */
  devicePrivateBytes?: Uint8Array;
}

/**
 * Result of a successful fresh-ceremony bootstrap.
 *
 * @public
 */
export interface CreateFreshResult {
  /**
   * Absolute storage key the yaml manifest was written to. Typically
   * `"/v/tn.yaml"`. Pass this to {@link BrowserRuntime.init} via
   * `opts.yamlPath` to load the freshly-minted ceremony.
   */
  yamlPath: string;
  /**
   * Newly-minted publisher DID (`did:key:z…`). 49 characters; uniquely
   * identifies this ceremony's emit-side identity for the lifetime of
   * the storage prefix.
   */
  did: string;
  /**
   * Ceremony id baked into the yaml — `"local_"` + 8 random hex chars.
   * Used by the wasm runtime as a chain-disambiguation prefix.
   */
  ceremonyId: string;
}

/** Encode a Uint8Array as a lowercase hex string. Pure JS. */
function _hexEncode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    const b = bytes[i] ?? 0;
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

/** Fill a fresh Uint8Array of `n` bytes with cryptographically-random bytes. */
function _randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

/**
 * Write a UTF-8 string under `path`. Convenience wrapper around the
 * adapter's `write` so call sites stay readable.
 */
function _writeUtf8(storage: JsStorageCallbacks, path: string, text: string): void {
  storage.write(path, new TextEncoder().encode(text));
}

/**
 * Mint a fresh ceremony in `storage` and write all required artefacts.
 *
 * Generates a new Ed25519 device key (or accepts a caller-supplied
 * seed via {@link CreateFreshOptions.devicePrivateBytes}), mints a
 * fresh BTN publisher state for the default group, auto-injects the
 * reserved `tn.agents` group, allocates an index-master HMAC key, and
 * writes the yaml + keystore layout the wasm runtime reads at init.
 *
 * @param storage - storage adapter the wasm runtime will use. Most
 *   callers pass the result of {@link localStorageStorageAdapter} or
 *   {@link memoryStorageAdapter}.
 * @param opts - optional knobs; see {@link CreateFreshOptions}.
 *
 * @returns A {@link CreateFreshResult} carrying the yaml path, DID,
 *   and ceremony id. Pass `yamlPath` to {@link BrowserRuntime.init} to
 *   load the freshly-minted ceremony.
 *
 * @throws Error - when `local.private` already exists under the
 *   resolved keystore prefix (clobber guard). Callers that want
 *   "init-or-reuse" should `storage.exists(...)` the yaml first and
 *   skip this function entirely on a hit.
 * @throws Error - when `opts.devicePrivateBytes` is supplied with a
 *   length other than 32.
 *
 * @example
 * ```ts
 * import { createFreshCeremony, memoryStorageAdapter } from "tn-proto/browser";
 *
 * const storage = memoryStorageAdapter();
 * const { yamlPath, did, ceremonyId } = createFreshCeremony(storage);
 * // -> { yamlPath: "/v/tn.yaml", did: "did:key:z6Mk…", ceremonyId: "local_a1b2c3d4" }
 * ```
 *
 * @example
 * ```ts
 * // Bind the ceremony to a pre-existing 32-byte seed (identity_seed bootstrap).
 * import { createFreshCeremony } from "tn-proto/browser";
 *
 * const result = createFreshCeremony(storage, {
 *   devicePrivateBytes: importedSeed,   // 32-byte Ed25519 seed
 *   root: "/my-app",
 *   stem: "main",
 * });
 * ```
 *
 * @see {@link createFromSeed} - bootstrap from server-provisioned
 *   seed + publisher state (witness-style flow). Use this when the
 *   server has already minted the publisher state.
 * @see {@link BrowserRuntime.init} - the higher-level wrapper that
 *   calls this on a fresh storage prefix and then loads the runtime.
 *
 * @remarks
 * Mirror of `createFreshCeremony` in `src/runtime/node_runtime.ts`.
 * Same yaml literal, same keystore filenames, same field order — a
 * yaml minted here is bit-equivalent to one minted by the Node side
 * modulo the ceremony id and device DID.
 *
 * @public
 */
export function createFreshCeremony(
  storage: JsStorageCallbacks,
  opts: CreateFreshOptions = {},
): CreateFreshResult {
  const root = opts.root ?? "/v";
  const stem = opts.stem ?? "tn";

  const yamlPath = `${root}/tn.yaml`;
  const keysDir = `${root}/.tn/${stem}/keys`;
  const logRel = `./.tn/${stem}/logs/tn.ndjson`;
  const adminRel = `./.tn/${stem}/admin/default.ndjson`;
  const keystoreRel = `./.tn/${stem}/keys`;

  const privatePath = `${keysDir}/local.private`;
  if (storage.exists(privatePath)) {
    throw new Error(
      `refusing to create a fresh ceremony at ${yamlPath}: ` +
        `${privatePath} already exists. Either clear the storage prefix to ` +
        `start over, or load the existing yaml directly (local.public holds ` +
        `the DID).`,
    );
  }

  // 1. Mint (or accept) the Ed25519 device key.
  let seed: Uint8Array;
  if (opts.devicePrivateBytes !== undefined) {
    if (opts.devicePrivateBytes.length !== 32) {
      throw new Error(
        `createFreshCeremony: devicePrivateBytes must be 32 bytes ` +
          `(Ed25519 seed); got ${opts.devicePrivateBytes.length}`,
      );
    }
    seed = new Uint8Array(opts.devicePrivateBytes);
  } else {
    seed = _randomBytes(32);
  }
  const dk = DeviceKey.fromSeed(seed);

  // 2. Mint the default-group btn publisher + self-kit.
  const btnSeed = _randomBytes(32);
  const pub = new BtnPublisher(btnSeed);
  const selfKit = pub.mint();
  const stateBytes = pub.toBytes();
  pub.free();

  // 3. Auto-inject the reserved `tn.agents` group (always cipher: btn).
  //    Matches createFreshCeremony in node_runtime.ts so a kit_bundle
  //    export can hand the LLM-runtime onboarding kit to a peer.
  const agentsBtnSeed = _randomBytes(32);
  const agentsPub = new BtnPublisher(agentsBtnSeed);
  const agentsSelfKit = agentsPub.mint();
  const agentsStateBytes = agentsPub.toBytes();
  agentsPub.free();

  // 4. Index master for HMAC-based field-hash tokens.
  const indexMaster = _randomBytes(32);

  // 5. Short local ceremony ID: "local_" + first 8 hex chars of random bytes.
  //    Matches the Node side's `"local_" + randomBytes(4).hex()`.
  const ceremonyId = `local_${_hexEncode(_randomBytes(4))}`;

  // 6. Write the keystore. Order matches the Node side so a fail
  //    half-way through leaves a recognisable partial state for a human
  //    debugger.
  storage.write(privatePath, seed);
  _writeUtf8(storage, `${keysDir}/local.public`, dk.did);
  storage.write(`${keysDir}/index_master.key`, indexMaster);
  storage.write(`${keysDir}/default.btn.state`, stateBytes);
  storage.write(`${keysDir}/default.btn.mykit`, selfKit);
  storage.write(`${keysDir}/tn.agents.btn.state`, agentsStateBytes);
  storage.write(`${keysDir}/tn.agents.btn.mykit`, agentsSelfKit);

  // 7. Write the yaml. Byte-for-byte the same template as
  //    `createFreshCeremony` in node_runtime.ts. The browser strips the
  //    `stdout` and `file.rotating` handlers — neither makes sense in a
  //    browser. The wasm runtime's own log write (via the storage
  //    callback) covers persistence.
  const yaml = `ceremony:
  id: ${ceremonyId}
  mode: local
  cipher: btn
  sign: true
  admin_log_location: ${adminRel}
  log_level: debug
logs:
  path: ${logRel}
keystore:
  path: ${keystoreRel}
handlers: []
device:
  device_identity: ${dk.did}
public_fields:
- timestamp
- event_id
- event_type
- level
- server_did
- user_did
- request_id
- method
- path
- ceremony_id
- cipher
- device_identity
- created_at
- group
- publisher_identity
- added_at
- leaf_index
- recipient_identity
- kit_sha256
- slot
- issued_to
- generation
- previous_kit_sha256
- old_pool_size
- new_pool_size
- rotated_at
- peer_identity
- package_sha256
- compiled_at
- absorbed_at
- vault_identity
- project_id
- linked_at
- reason
- unlinked_at
- policy_uri
- content_hash
- event_types_covered
- policy_text
- envelope_event_id
- envelope_device_identity
- envelope_event_type
- envelope_sequence
- invalid_reasons
default_policy: private
groups:
  default:
    policy: private
    cipher: btn
    recipients:
    - recipient_identity: ${dk.did}
  tn.agents:
    policy: private
    cipher: btn
    recipients:
    - recipient_identity: ${dk.did}
    fields:
    - instruction
    - use_for
    - do_not_use_for
    - consequences
    - on_violation_or_error
    - policy
    auto_populated_by_policy: true
fields: {}
`;
  _writeUtf8(storage, yamlPath, yaml);

  return { yamlPath, did: dk.did, ceremonyId };
}
