/**
 * Browser-side bootstrap from a caller-supplied seed + publisher state.
 *
 * Sister to `create_fresh.ts`. Where {@link createFreshCeremony} mints
 * every secret on the JS side, {@link createFromSeed} adopts secrets
 * the caller already has — typically server-minted, baked into a
 * per-agreement delivery template. The yaml + keystore layout is
 * identical (the same wasm runtime reads the same files); only the
 * source of the seed + publisher-state bytes differs.
 *
 * ## Use-case anchor
 *
 * The witness harness today ships a `(seed, did, btn_publisher_state)`
 * triple per agreement so the browser can emit signed envelopes
 * without having to mint a fresh ceremony at page load. This module is
 * the JS port of that bootstrap.
 *
 * ## On-the-fly mints
 *
 * These are written even when the caller doesn't logically need them
 * — the wasm runtime's init reads each one during the bring-up
 * sequence:
 *
 * - `default.btn.mykit` — minted from the supplied publisher state.
 *   Consumes one leaf in the publisher's tree; emit-only callers can
 *   ignore it.
 * - `index_master.key` — fresh 32 random bytes unless the caller
 *   supplies one. Field-hash tokens hash with this; for emit-only
 *   transient sessions a fresh one per page load is fine.
 * - `tn.agents` group state + self-kit — minted fresh. The yaml
 *   schema requires the reserved group to exist; we honor that with a
 *   private group nobody outside this runtime can read.
 *
 * @packageDocumentation
 */

import { DeviceKey } from "../core/signing.js";
import { BtnPublisher } from "../raw.js";
import type { JsStorageCallbacks } from "../runtime/storage_node.js";

/**
 * Inputs for {@link createFromSeed}. Server-provisioned credentials
 * are required; everything else has sensible defaults.
 *
 * @public
 */
export interface CreateFromSeedOptions {
  /**
   * 32-byte Ed25519 seed. Typically delivered from a server that
   * minted it at agreement-creation time.
   */
  seed: Uint8Array;
  /**
   * Pre-minted `BtnPublisher.toBytes()` for the default group. The
   * server creates the publisher (one per agreement / session) and
   * sends its serialized state to the client.
   */
  btnPublisherState: Uint8Array;
  /**
   * Optional 32-byte HMAC master for field-hash index tokens. If
   * omitted, a fresh one is generated — fine for emit-only flows
   * where nobody is going to query by field-hash.
   */
  indexMaster?: Uint8Array;
  /**
   * Storage prefix root. Default: `"/v"` — matches `createFreshCeremony`
   * so a `Tn.init` and a `Tn.initFromSeed` produce yaml at the same key.
   */
  root?: string;
  /** Yaml stem (used in the keystore / log / admin path templates).
   *  Default: `"tn"`. */
  stem?: string;
  /**
   * Optional ceremony id. Default: `local_<8 random hex>`.
   * Useful when the server wants every browser session pinned to a
   * known ceremony id (e.g. an agreement id).
   */
  ceremonyId?: string;
}

/**
 * Result of {@link createFromSeed}.
 *
 * @public
 */
export interface CreateFromSeedResult {
  /**
   * Absolute storage key the synthesised yaml manifest was written to.
   * Pass to {@link BrowserRuntime.init} via `opts.yamlPath`.
   */
  yamlPath: string;
  /**
   * DID derived from the supplied seed. Matches what
   * `DeviceKey.fromSeed(opts.seed).did` would return.
   */
  did: string;
  /**
   * Ceremony id baked into the yaml. Either `opts.ceremonyId` (when
   * supplied) or `"local_" + 8 random hex chars`.
   */
  ceremonyId: string;
}

function _hexEncode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    const b = bytes[i] ?? 0;
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

function _randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

function _writeUtf8(storage: JsStorageCallbacks, path: string, text: string): void {
  storage.write(path, new TextEncoder().encode(text));
}

/**
 * Adopt a caller-supplied seed + BTN publisher state, synthesise the
 * yaml + keystore files the wasm runtime needs, and write them to
 * `storage`.
 *
 * The result of this call leaves `storage` in the same shape
 * {@link createFreshCeremony} would have produced, but with the device
 * identity bound to the caller's bytes instead of newly-minted ones.
 * Subsequent `BrowserRuntime.init({yamlPath: result.yamlPath, storage})`
 * loads it.
 *
 * @param storage - storage adapter the wasm runtime will use. For the
 *   witness pattern (no persistence between sessions), pass a fresh
 *   {@link memoryStorageAdapter} per page load.
 * @param opts - seed + publisher state and (optionally) ceremony
 *   knobs; see {@link CreateFromSeedOptions}.
 *
 * @returns A {@link CreateFromSeedResult} carrying the yaml path, the
 *   DID derived from `opts.seed`, and the ceremony id.
 *
 * @throws Error - when `opts.seed.length !== 32`.
 * @throws Error - when `opts.btnPublisherState.length === 0`.
 * @throws Error - when `opts.indexMaster` is supplied with a length
 *   other than 32.
 * @throws Error - when `local.private` already exists under the
 *   resolved keystore prefix (clobber guard). Callers reusing an
 *   adapter across sessions should clear it first or hand in a fresh
 *   one.
 *
 * @example
 * ```ts
 * import { createFromSeed, memoryStorageAdapter } from "@tnproto/sdk/browser";
 *
 * // Server-delivered credentials (e.g. from the witness's delivery template).
 * const storage = memoryStorageAdapter();
 * const { yamlPath, did } = createFromSeed(storage, {
 *   seed: b64decode(PUBLISHER_SEED_B64),
 *   btnPublisherState: b64decode(BTN_PUBLISHER_STATE_B64),
 *   ceremonyId: agreementId,   // optional: pin to the server's id
 * });
 * // did matches DeviceKey.fromSeed(PUBLISHER_SEED).did
 * ```
 *
 * @see {@link createFreshCeremony} - the "no caller bytes, mint
 *   everything" variant.
 * @see {@link Tn.initFromSeed} - the higher-level wrapper that calls
 *   this and returns a usable `Tn` instance with handlers wired up.
 *
 * @remarks
 * The yaml written here is byte-identical to what `createFreshCeremony`
 * produces (same template, same field order, same `tn.agents` block),
 * differing only in the device DID and the optional ceremony id.
 *
 * @public
 */
export function createFromSeed(
  storage: JsStorageCallbacks,
  opts: CreateFromSeedOptions,
): CreateFromSeedResult {
  if (opts.seed.length !== 32) {
    throw new Error(`createFromSeed: seed must be 32 bytes, got ${opts.seed.length}`);
  }
  if (opts.btnPublisherState.length === 0) {
    throw new Error("createFromSeed: btnPublisherState must be non-empty");
  }
  if (opts.indexMaster !== undefined && opts.indexMaster.length !== 32) {
    throw new Error(
      `createFromSeed: indexMaster must be 32 bytes, got ${opts.indexMaster.length}`,
    );
  }

  const root = opts.root ?? "/v";
  const stem = opts.stem ?? "tn";

  const yamlPath = `${root}/tn.yaml`;
  const keysDir = `${root}/.tn/${stem}/keys`;
  const logRel = `./.tn/${stem}/logs/tn.ndjson`;
  const adminRel = `./.tn/${stem}/admin/admin.ndjson`;
  const keystoreRel = `./.tn/${stem}/keys`;

  const privatePath = `${keysDir}/local.private`;
  if (storage.exists(privatePath)) {
    throw new Error(
      `refusing to bootstrap-from-seed at ${yamlPath}: ` +
        `${privatePath} already exists. The caller is reusing a storage ` +
        `adapter across sessions — hand in a fresh in-memory adapter (or ` +
        `clear the existing one) before calling Tn.initFromSeed again.`,
    );
  }

  // 1. Derive the DID from the seed. `DeviceKey.fromSeed` ultimately
  //    calls the wasm primitive `deviceKeyFromSeed`, so the encoding
  //    matches what Python / Node / the witness server produce
  //    byte-for-byte.
  const dk = DeviceKey.fromSeed(new Uint8Array(opts.seed));

  // 2. Restore the publisher state the caller handed in, mint our
  //    self-kit, snapshot the updated state. The self-kit consumes one
  //    leaf in the tree — emit-only callers don't care, readers need
  //    it to decrypt their own log.
  const pub = BtnPublisher.fromBytes(new Uint8Array(opts.btnPublisherState));
  const selfKit = pub.mint();
  const stateBytes = pub.toBytes();
  pub.free();

  // 3. Reserved `tn.agents` group. Minted fresh — the witness style
  //    doesn't carry agents-policy material, so a per-session group
  //    that nobody outside this runtime can read is the right default.
  const agentsBtnSeed = _randomBytes(32);
  const agentsPub = new BtnPublisher(agentsBtnSeed);
  const agentsSelfKit = agentsPub.mint();
  const agentsStateBytes = agentsPub.toBytes();
  agentsPub.free();

  // 4. Index master — caller's or fresh.
  const indexMaster = opts.indexMaster
    ? new Uint8Array(opts.indexMaster)
    : _randomBytes(32);

  // 5. Ceremony id — caller's or fresh `local_<hex>`.
  const ceremonyId = opts.ceremonyId ?? `local_${_hexEncode(_randomBytes(4))}`;

  // 6. Write keystore in the same order as createFreshCeremony so a
  //    debugger sees a recognisable partial state on a half-write.
  storage.write(privatePath, new Uint8Array(opts.seed));
  _writeUtf8(storage, `${keysDir}/local.public`, dk.did);
  storage.write(`${keysDir}/index_master.key`, indexMaster);
  storage.write(`${keysDir}/default.btn.state`, stateBytes);
  storage.write(`${keysDir}/default.btn.mykit`, selfKit);
  storage.write(`${keysDir}/tn.agents.btn.state`, agentsStateBytes);
  storage.write(`${keysDir}/tn.agents.btn.mykit`, agentsSelfKit);

  // 7. Yaml. Same template as createFreshCeremony so the wasm runtime
  //    can't tell the two bootstrap paths apart. Only the device id +
  //    ceremony id differ (caller-supplied) — everything else is byte-
  //    identical.
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
- to_did
- issued_to
- generation
- previous_kit_sha256
- old_pool_size
- new_pool_size
- rotated_at
- peer_identity
- package_sha256
- compiled_at
- from_did
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
