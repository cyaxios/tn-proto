// tn.seal / tn.unseal — browser entry adapter.
//
// Wraps the runtime-agnostic pipeline in `core/sealed_object.ts` around
// the browser ceremony's storage adapter: the yaml is parsed into the
// routing view the seal classifier needs, group publisher material and
// reader kits are read from the same storage slots the wasm runtime
// uses, and the receipt row chains through the live runtime's normal
// write path. The browser has no filesystem, so `asRecipient` takes a
// plain {filename -> bytes} key bag using the same keystore filenames
// the Node side walks (`<group>.btn.mykit`, `<group>.jwe.mykey`, ...).
//
// hibe stays Node/Python territory for now: the browser walk skips
// hibe material rather than pretending to open it.

import { parse as parseYaml } from "yaml";

import { BtnPublisher, signMessage } from "../raw.js";
import type { GroupKits } from "../core/decrypt.js";
import { jweSeal } from "../core/jwe.js";
import {
  sealObjectCore,
  unsealObjectCore,
  type SealContext,
  type SealGroupView,
  type SealOptions,
  type SealedObject,
  type SealedTriple,
  type UnsealCoreOptions,
  type UnsealKitSource,
  type UnsealSource,
} from "../core/sealed_object.js";
import { signatureB64 } from "../core/signing.js";
import type { Entry } from "../Entry.js";
import type { JsStorageCallbacks } from "../runtime/storage_node.js";
import type { BrowserRuntime } from "./runtime.js";

/** The browser analog of a recipient keystore directory: keystore
 * filenames mapped to raw key bytes (e.g. `"default.jwe.mykey"` ->
 * 32 private-key bytes). */
export type BrowserKeyBag = Record<string, Uint8Array>;

/** Options for the browser `tn.unseal`. Same verify/raw semantics as
 * the Node entry; only the `asRecipient` shape differs (a key bag
 * instead of a directory path — the browser has no directories). */
export interface BrowserUnsealOptions extends UnsealCoreOptions {
  /** Bring-your-own-key override. When set, only
   * {@link BrowserUnsealOptions.group} is decrypted and the active
   * ceremony (if any) is not consulted. */
  asRecipient?: BrowserKeyBag;
  /** The group the `asRecipient` override opens (default `"default"`).
   * Ignored on the default walk, which tries every block. */
  group?: string;
}

/** The slice of the ceremony yaml the seal/unseal pipeline needs,
 * plus the resolved keystore prefix. Mirrors the corresponding
 * branches of `runtime/config.ts::loadConfig` (public_fields,
 * per-group `fields:` routing with the flat `fields:` fallback,
 * cipher inheritance, default-group injection). */
interface CeremonyView {
  ceremonyId: string;
  deviceIdentity: string;
  publicFields: Set<string>;
  fieldToGroups: Map<string, string[]>;
  groups: Map<string, SealGroupView>;
  keystorePath: string;
}

function _dirOf(path: string): string {
  const i = path.lastIndexOf("/");
  return i <= 0 ? "" : path.slice(0, i);
}

/** Resolve a yaml-relative path against the yaml's directory using the
 * storage adapter's own `/`-separated key convention. */
function _resolvePath(yamlDir: string, rel: string): string {
  if (rel.startsWith("/")) return rel;
  const stripped = rel.replace(/^\.\//, "");
  return yamlDir === "" ? `/${stripped}` : `${yamlDir}/${stripped}`;
}

function _loadView(storage: JsStorageCallbacks, yamlPath: string): CeremonyView {
  const doc =
    (parseYaml(new TextDecoder().decode(storage.read(yamlPath))) as Record<string, unknown>) ??
    {};
  const ceremony = (doc.ceremony ?? {}) as Record<string, unknown>;
  const device = (doc.device ?? {}) as Record<string, unknown>;
  const keystore = (doc.keystore ?? {}) as Record<string, unknown>;

  const publicFields = new Set<string>(
    Array.isArray(doc.public_fields) ? (doc.public_fields as unknown[]).map(String) : [],
  );

  const groupsDoc = (doc.groups ?? {}) as Record<string, unknown>;
  const groups = new Map<string, SealGroupView>();
  const perGroupFields = new Map<string, string[]>();
  let anyGroupDeclaresFields = false;
  for (const [name, raw] of Object.entries(groupsDoc)) {
    const g = (raw ?? {}) as Record<string, unknown>;
    groups.set(name, {
      cipher: String(g.cipher ?? ceremony.cipher ?? "btn"),
      indexEpoch: Number(g.index_epoch ?? 0) || 0,
      aadDefault: (g.aad !== null && typeof g.aad === "object" && !Array.isArray(g.aad)
        ? g.aad
        : {}) as Record<string, unknown>,
    });
    if (Array.isArray(g.fields)) {
      anyGroupDeclaresFields = true;
      perGroupFields.set(name, (g.fields as unknown[]).map(String));
    }
  }
  if (!groups.has("default")) {
    groups.set("default", {
      cipher: String(ceremony.cipher ?? "btn"),
      indexEpoch: 0,
      aadDefault: {},
    });
  }

  const fieldToGroups = new Map<string, string[]>();
  const add = (fname: string, gname: string): void => {
    const list = fieldToGroups.get(fname) ?? [];
    if (!list.includes(gname)) list.push(gname);
    fieldToGroups.set(fname, list);
  };
  if (anyGroupDeclaresFields) {
    for (const [gname, fnames] of perGroupFields) {
      for (const fname of fnames) add(fname, gname);
    }
  } else {
    for (const [fname, fspec] of Object.entries((doc.fields ?? {}) as Record<string, unknown>)) {
      if (typeof fspec === "string") {
        add(fname, fspec);
      } else if (fspec !== null && typeof fspec === "object" && "group" in fspec) {
        add(fname, String((fspec as Record<string, unknown>).group ?? "default"));
      }
    }
  }
  for (const [fname, gnames] of fieldToGroups) {
    fieldToGroups.set(fname, [...new Set(gnames)].sort());
  }

  return {
    ceremonyId: String(ceremony.id ?? ""),
    deviceIdentity: String(device.device_identity ?? ""),
    publicFields,
    fieldToGroups,
    groups,
    keystorePath: _resolvePath(_dirOf(yamlPath), String(keystore.path ?? "./.tn/tn/keys")),
  };
}

function _readOr(storage: JsStorageCallbacks, path: string): Uint8Array | null {
  return storage.exists(path) ? storage.read(path) : null;
}

/** Numeric archive index from a filename suffix; non-numeric suffixes
 * sort last (same tolerance as `runtime/keystore.ts::archiveIndex`). */
function _archiveIndex(suffix: string): number {
  return /^\d+$/.test(suffix) ? Number(suffix) : Number.NEGATIVE_INFINITY;
}

/** Order archive names newest-first per their numeric suffix after
 * `prefix`; ties (and non-numeric fallbacks) keep lexicographic-desc
 * order, mirroring the Node loaders. */
function _newestFirst(names: string[], prefix: string): string[] {
  return [...names].sort((a, b) => {
    const ai = _archiveIndex(a.slice(prefix.length));
    const bi = _archiveIndex(b.slice(prefix.length));
    if (bi > ai) return 1;
    if (bi < ai) return -1;
    return b.localeCompare(a);
  });
}

/** Btn/jwe candidate walk over a filename->bytes view. `names` is every
 * available filename; `readBytes` resolves one. Mirrors the ordering of
 * `runtime/keystore.ts::loadBtnKits` / `loadJweKeys`: active first,
 * then `.retired.<epoch>` newest-first, then `.revoked.<ts>` newest-
 * first. hibe material is skipped (not wired for the browser). */
function _candidatesFrom(
  group: string,
  names: string[],
  readBytes: (name: string) => Uint8Array | null,
): GroupKits[] {
  const out: GroupKits[] = [];

  const btnKits: Uint8Array[] = [];
  const active = readBytes(`${group}.btn.mykit`);
  if (active !== null) btnKits.push(active);
  for (const prefix of [`${group}.btn.mykit.retired.`, `${group}.btn.mykit.revoked.`]) {
    for (const name of _newestFirst(names.filter((n) => n.startsWith(prefix)), prefix)) {
      const bytes = readBytes(name);
      if (bytes !== null) btnKits.push(bytes);
    }
  }
  if (btnKits.length > 0) out.push({ cipher: "btn", kits: btnKits });

  const jweKeys: Uint8Array[] = [];
  const currentJwe = readBytes(`${group}.jwe.mykey`);
  if (currentJwe !== null) jweKeys.push(currentJwe);
  const revokedJwePrefix = `${group}.jwe.mykey.revoked.`;
  for (const name of names.filter((n) => n.startsWith(revokedJwePrefix)).sort().reverse()) {
    const bytes = readBytes(name);
    if (bytes !== null) jweKeys.push(bytes);
  }
  if (jweKeys.length > 0) out.push({ cipher: "jwe", kits: jweKeys });

  return out;
}

/** Kit source over the ceremony's own storage keystore. */
function _storageKitSource(storage: JsStorageCallbacks, view: CeremonyView): UnsealKitSource {
  const ks = view.keystorePath;
  let names: string[] | null = null;
  const listNames = (): string[] => {
    if (names === null) {
      try {
        names = storage.list(ks).map((p) => (p.startsWith(`${ks}/`) ? p.slice(ks.length + 1) : p));
      } catch {
        names = [];
      }
    }
    return names;
  };
  return {
    forGroup: (group) => ({
      ownCipher: view.groups.get(group)?.cipher,
      candidates: _candidatesFrom(group, listNames(), (name) =>
        _readOr(storage, `${ks}/${name}`),
      ),
    }),
  };
}

/** Kit source over a caller-supplied {filename -> bytes} bag. An empty
 * candidate list for the requested group is an error, mirroring the
 * Node `asRecipient` directory walk. */
function _bagKitSource(bag: BrowserKeyBag): UnsealKitSource {
  const names = Object.keys(bag);
  const readBytes = (name: string): Uint8Array | null =>
    Object.hasOwn(bag, name) ? bag[name]! : null;
  return {
    forGroup: (group) => {
      const candidates = _candidatesFrom(group, names, readBytes);
      if (candidates.length === 0) {
        throw new Error(
          `unseal: no recipient key found for group=${JSON.stringify(group)} in ` +
            `the supplied key bag. Looked for ${group}.btn.mykit (btn) and ` +
            `${group}.jwe.mykey (jwe).`,
        );
      }
      return { candidates };
    },
  };
}

/** Seal one group's plaintext from browser storage material. Same
 * failure texts as the Node `_sealGroup` so errors propagate consistently
 * from both entry points. */
async function _sealGroupBrowser(
  storage: JsStorageCallbacks,
  keystorePath: string,
  gname: string,
  cipher: string,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  if (cipher === "btn") {
    const stateBytes = _readOr(storage, `${keystorePath}/${gname}.btn.state`);
    if (stateBytes === null) {
      throw new Error("btn: no state file in this keystore");
    }
    // Publisher state is static between rotations, so restoring from the
    // stored bytes per seal is side-effect-free (encrypt mints a fresh
    // body key; it never advances persisted state).
    return BtnPublisher.fromBytes(stateBytes).encrypt(plaintext);
  }
  if (cipher === "jwe") {
    const path = `${keystorePath}/${gname}.jwe.recipients`;
    const raw = _readOr(storage, path);
    if (raw === null) {
      throw new Error(`jwe: no recipients file for group ${JSON.stringify(gname)} at ${path}`);
    }
    const doc = JSON.parse(new TextDecoder().decode(raw)) as { pub_b64: string }[];
    const pubs = doc.map((e) => {
      const bin = atob(e.pub_b64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return bytes;
    });
    return jweSeal(pubs, plaintext, aad.length > 0 ? aad : undefined);
  }
  throw new Error(`cipher ${JSON.stringify(cipher)} has no browser publisher path`);
}

/**
 * Seal `fields` into a portable attested object using the browser
 * ceremony's storage-held config + key material. The receipt row (on
 * by default) chains through the live wasm write path, exactly like an
 * ordinary emit. See `core/sealed_object.ts::sealObjectCore` for the
 * pipeline; mirrors `python/tn/seal.py::seal`.
 */
export async function sealWithBrowserRuntime(
  rt: BrowserRuntime,
  objectType: string,
  fields: Record<string, unknown> = {},
  opts: SealOptions = {},
): Promise<SealedObject> {
  const view = _loadView(rt.storage, rt.yamlPath);
  const ks = view.keystorePath;
  const seed = _readOr(rt.storage, `${ks}/local.private`);
  if (seed === null) {
    throw new Error(`seal: device seed not found at ${ks}/local.private`);
  }
  const indexMaster = _readOr(rt.storage, `${ks}/index_master.key`);
  if (indexMaster === null) {
    throw new Error(`seal: index master key not found at ${ks}/index_master.key`);
  }
  const ctx: SealContext = {
    ceremonyId: view.ceremonyId,
    deviceIdentity: view.deviceIdentity,
    publicFields: view.publicFields,
    fieldToGroups: view.fieldToGroups,
    groups: view.groups,
    indexMaster,
    signB64: (bytes) => String(signatureB64(signMessage(seed, bytes))),
    sealGroup: (gname, cipher, plaintext, aad) =>
      _sealGroupBrowser(rt.storage, ks, gname, cipher, plaintext, aad),
    // The runtime-level verb (not Tn.info) so the receipt carries no
    // context-stack fields — same as the Node adapter, which routes
    // through rt.emitAsync directly.
    emitReceipt: (receiptFields) => {
      rt.info("tn.object.sealed", receiptFields);
    },
  };
  return sealObjectCore(ctx, objectType, fields, opts);
}

/**
 * Verify a sealed object and open every group block a held key fits,
 * sourcing keys from the browser ceremony's storage (or, with
 * `asRecipient`, from a caller-supplied key bag — no ceremony needed).
 * See `core/sealed_object.ts::unsealObjectCore`; mirrors
 * `python/tn/seal.py::unseal`.
 */
export async function unsealWithBrowserRuntime(
  rt: BrowserRuntime | null,
  source: UnsealSource,
  opts: BrowserUnsealOptions = {},
): Promise<Entry | SealedTriple> {
  const own: UnsealKitSource | null =
    rt === null ? null : _storageKitSource(rt.storage, _loadView(rt.storage, rt.yamlPath));
  const asRecipient: UnsealKitSource | null =
    opts.asRecipient === undefined ? null : _bagKitSource(opts.asRecipient);
  return unsealObjectCore(own, asRecipient, opts.group ?? "default", source, {
    verify: opts.verify,
    raw: opts.raw,
  });
}
