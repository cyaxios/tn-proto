// tn.seal / tn.unseal — portable sealed objects, Node entry.
//
// A sealed object is a standalone envelope: the same on-wire schema the
// log writes, built and returned instead of appended to the log. `seal`
// routes fields into groups per the yaml and encrypts each group;
// `unseal` verifies the envelope and opens every group block the keys
// at hand can decrypt, walking own-ceremony ciphers first and then
// every kit in the keystore.
//
// The pipeline itself lives in `core/sealed_object.ts` (browser-safe;
// the browser entry wraps the same core around its storage adapter).
// This module is the Node adapter: it sources group material from the
// keystore directory on disk and chains receipts through the
// NodeRuntime's async write path. Mirrors python/tn/seal.py (the
// normative reference). Async-first: jwe seals and opens through
// panva/jose, which is async-only in TS, so both verbs return promises
// for every cipher.

import { Buffer } from "node:buffer";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

import { BtnPublisher } from "./raw.js";
import { type GroupKits } from "./core/decrypt.js";
import { jweSeal } from "./core/jwe.js";
import {
  sealObjectCore,
  unsealObjectCore,
  type SealContext,
  type SealOptions,
  type SealedObject,
  type SealedTriple,
  type UnsealCoreOptions,
  type UnsealKitSource,
  type UnsealSource,
} from "./core/sealed_object.js";
import { signatureB64 } from "./core/signing.js";
import type { Entry } from "./Entry.js";
import { hibeCandidateKeys, hibeEncrypt, loadHibeGroup } from "./runtime/hibe_group.js";
import { loadBtnKits, loadJweKeys } from "./runtime/keystore.js";
import type { NodeRuntime } from "./runtime/node_runtime.js";

export { SealedObject, SealedObjectError } from "./core/sealed_object.js";
export type { SealOptions, SealedTriple, UnsealSource } from "./core/sealed_object.js";

/** Options for {@link unsealWithRuntime} / `tn.unseal`. */
export interface UnsealOptions extends UnsealCoreOptions {
  /** Bring-your-own-kit override: a directory holding recipient key
   * files (`<group>.btn.mykit` / `<group>.jwe.mykey` /
   * `<group>.hibe.sk`). When set, only {@link UnsealOptions.group} is
   * decrypted and the active ceremony (if any) is not consulted. */
  asRecipient?: string;
  /** The group the `asRecipient` override opens (default `"default"`).
   * Ignored on the default walk, which tries every block. */
  group?: string;
}

/** Seal one group's plaintext under its declared cipher — the same
 * publisher material the runtime's write pipeline uses
 * (`_sealGroupTs` + the async jwe pre-seal), sourced from the loaded
 * keystore. Throws when this keystore holds no publisher-side
 * material for the group. */
async function _sealGroup(
  rt: NodeRuntime,
  gname: string,
  cipher: string,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  if (cipher === "hibe") {
    const mat = rt.keystore.groups.get(gname)?.hibe;
    if (!mat) {
      throw new Error("HIBE: no authority mpk / identity path in this keystore");
    }
    return hibeEncrypt(mat, plaintext, aad);
  }
  if (cipher === "btn") {
    const stateBytes = rt.keystore.groups.get(gname)?.stateBytes;
    if (!stateBytes) {
      throw new Error("btn: no state file in this keystore");
    }
    // Publisher state is static between rotations, so restoring from the
    // loaded bytes per seal is side-effect-free (encrypt mints a fresh
    // body key; it never advances persisted state).
    return BtnPublisher.fromBytes(stateBytes).encrypt(plaintext);
  }
  if (cipher === "jwe") {
    const path = join(rt.config.keystorePath, `${gname}.jwe.recipients`);
    if (!existsSync(path)) {
      throw new Error(`jwe: no recipients file for group ${JSON.stringify(gname)} at ${path}`);
    }
    const doc = JSON.parse(readFileSync(path, "utf8")) as { pub_b64: string }[];
    const pubs = doc.map((e) => new Uint8Array(Buffer.from(e.pub_b64, "base64")));
    return jweSeal(pubs, plaintext, aad.length > 0 ? aad : undefined);
  }
  throw new Error(`cipher ${JSON.stringify(cipher)} has no TS publisher path`);
}

/**
 * Seal `fields` into a portable attested object (standalone envelope).
 *
 * Same classification / index-token / aad-bind / encrypt pipeline as
 * the runtime's write path, then the standalone identity: `sequence`
 * 0, `prev_hash` "", `level` "", the reserved public marker
 * `tn_sealed: 1`, always signed. The ceremony's chain state is never
 * touched. Mirrors `python/tn/seal.py::seal`.
 */
export async function sealWithRuntime(
  rt: NodeRuntime,
  objectType: string,
  fields: Record<string, unknown> = {},
  opts: SealOptions = {},
): Promise<SealedObject> {
  const cfg = rt.config;
  const groups = new Map(
    [...cfg.groups].map(([name, g]) => [
      name,
      { cipher: g.cipher, indexEpoch: g.indexEpoch, aadDefault: g.aadDefault ?? {} },
    ]),
  );
  const ctx: SealContext = {
    ceremonyId: cfg.ceremonyId,
    deviceIdentity: cfg.device.device_identity,
    publicFields: cfg.publicFields,
    fieldToGroups: cfg.fieldToGroups,
    groups,
    indexMaster: rt.keystore.indexMaster,
    signB64: (bytes) => String(signatureB64(rt.keystore.device.sign(bytes))),
    sealGroup: (gname, cipher, plaintext, aad) => _sealGroup(rt, gname, cipher, plaintext, aad),
    emitReceipt: async (receiptFields) => {
      // Routed through the runtime's async write path (jwe groups seal
      // asynchronously in TS); errors PROPAGATE — the caller asked for
      // a receipt, so a silently missing one would break the guarantee.
      await rt.emitAsync("info", "tn.object.sealed", receiptFields);
    },
  };
  return sealObjectCore(ctx, objectType, fields, opts);
}

/** Every decrypt-kit candidate a keystore directory holds for `group`,
 * in the fixed btn → jwe → hibe order (the same order as
 * read_as_recipient / Python's `_discover_keybag_ciphers`). Each
 * candidate carries its full multi-kit list — rotation-archived btn
 * kits and jwe keys included — so pre-rotation objects still open. */
function _keystoreCandidates(keystoreDir: string, group: string): GroupKits[] {
  const out: GroupKits[] = [];
  const btnKits = loadBtnKits(keystoreDir, group);
  if (btnKits.length > 0) out.push({ cipher: "btn", kits: btnKits });
  const jweKeys = loadJweKeys(keystoreDir, group);
  if (jweKeys.length > 0) out.push({ cipher: "jwe", kits: jweKeys });
  if (existsSync(join(keystoreDir, `${group}.hibe.sk`))) {
    const mat = loadHibeGroup(keystoreDir, group);
    if (mat !== null) out.push({ cipher: "hibe", kits: hibeCandidateKeys(mat), mpk: mat.mpk });
  }
  return out;
}

/** As {@link _keystoreCandidates} but for the `asRecipient` override:
 * an empty candidate list is an error (the caller pointed at a
 * directory that holds no key for the group). Mirrors
 * `seal.py::_load_recipient_candidates`. */
function _loadRecipientCandidates(keystoreDir: string, group: string): GroupKits[] {
  const candidates = _keystoreCandidates(keystoreDir, group);
  if (candidates.length === 0) {
    throw new Error(
      `unseal: no recipient key found for group=${JSON.stringify(group)} in ` +
        `${keystoreDir}. Looked for ${group}.btn.mykit (btn), ` +
        `${group}.jwe.mykey (jwe), and ${group}.hibe.sk (hibe). If you ` +
        `absorbed a kit_bundle, the kit lands in your ceremony's ` +
        `keystore — point asRecipient there.`,
    );
  }
  return candidates;
}

/**
 * Verify a sealed object and open every group block a held key fits.
 *
 * No key fitting is not an error: you get the verified public frame
 * with the blocks left sealed (listed in `Entry.hidden_groups`).
 * `SealedObjectError` is malformed input only; `VerifyError` is failed
 * verification with `verify: true` (`failed_checks` drawn from
 * `"signature"` / `"row_hash"`). Mirrors `python/tn/seal.py::unseal`.
 *
 * `rt` may be `null` (no active ceremony): verification still runs and
 * the `asRecipient` override still opens its group; the default
 * keystore walk is skipped.
 */
export async function unsealWithRuntime(
  rt: NodeRuntime | null,
  source: UnsealSource,
  opts: UnsealOptions = {},
): Promise<Entry | SealedTriple> {
  const own: UnsealKitSource | null =
    rt === null
      ? null
      : {
          forGroup: (gname) => ({
            ownCipher: rt.config.groups.get(gname)?.cipher,
            candidates: _keystoreCandidates(rt.config.keystorePath, gname),
          }),
        };
  const asRecipientDir = opts.asRecipient;
  const asRecipient: UnsealKitSource | null =
    asRecipientDir === undefined
      ? null
      : {
          forGroup: (gname) => ({
            candidates: _loadRecipientCandidates(asRecipientDir, gname),
          }),
        };
  return unsealObjectCore(own, asRecipient, opts.group ?? "default", source, {
    verify: opts.verify,
    raw: opts.raw,
  });
}
