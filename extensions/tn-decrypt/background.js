// Service worker: owns keystore storage and in-memory kits.
//
// Multi-keystore model
// --------------------
//
// chrome.storage.local:
//   keystores: [
//     // "vault" source (default for legacy entries without `source`):
//     { id, label, added_at, source: "vault", blob, emk_wrapped_secret? },
//     // "local-file" source (file imported from disk; stored plaintext):
//     { id, label, added_at, source: "local-file", filename, bundle },
//     // "vault-paired" source (received from the vault's /extension-pair
//     //  page after the user signed in there and tapped "Pair"; resolves
//     //  O-9 — D-1/D-3/D-20/D-22 hybrid pairing flow):
//     //  vault-paired entries are ONE PROJECT/GROUP per row — the vault
//     //  pair page already unwrapped the BEK with the AWK and decrypted
//     //  the body, then forwarded each <group>.btn.mykit (+ optional
//     //  state) verbatim. Stored plaintext (kit IS the bearer credential).
//     { id, label, added_at, source: "vault-paired", project_id,
//       project_label, group, account_label, paired_at, bundle },
//     ...
//   ]
//     `vault` blobs are passphrase-encrypted (AES-GCM under PBKDF2-SHA256).
//     `emk_wrapped_secret` (optional, vault only) is the same passphrase
//     wrapped under the extension master key (EMK), so a single passkey
//     tap unlocks every keystore that has been bound to the EMK.
//
//     `local-file` entries hold the plaintext keystore-v1 bundle
//     directly. The source file is already on disk in the user's
//     filesystem, so wrapping it in passphrase-encrypted storage here
//     is security theater. These entries are auto-loaded into memory
//     at service-worker startup and report `unlocked: true`
//     unconditionally — there's nothing to unlock.
//   order: [id, id, ...]
//     Resolution order when two keystores hold kits for the same
//     publisher_id (rotation-preserved scenarios, or multiple imports
//     from the same ceremony). Default: most-recently-unlocked first.
//   extension_unlock: {
//     kind: "prf" | "passphrase",
//     verifier: { nonce_b64, ciphertext_b64 },
//     // PRF only:
//     credential_id_b64?, prf_salt_b64?, rp_id?,
//     // passphrase fallback only:
//     kdf_salt_b64?, kdf_iterations?,
//   }
//     Present iff the user has set up extension-wide unlock. Absent
//     means we fall back entirely to per-keystore passphrases.
//
// In-memory (lives only for as long as the SW is alive):
//   unlocked: Map<keystoreId, { label, kits: Map<publisher_id_hex, Uint8Array[]> }>
//   emk: CryptoKey | null   (current session's extension master key)
//
// A ciphertext is classified by walking `order`, trying each kit in
// each keystore until one unseals. If none unseal but the ciphertext
// parses as a valid btn ciphertext, return "sealed" (gray pill). If
// it doesn't parse, "not-tn" (no UI change).

// Wasm primitives (btnDecrypt, btnKitPublisherId, ...) are loaded via
// `wasm_loader.js`, which is the single-flight init shared with the
// dashboard pattern. We pull the namespace at call time rather than at
// module-load time so the loader (and its `[ext:wasm]` log breadcrumb)
// fires lazily on the first decrypt request.
import { loadTnWasm } from "./wasm_loader.js";

import {
  bytesToB64, b64ToBytes, rand,
  importEmk, deriveEmkFromPassphrase, emkFromPrfOutput,
  makeVerifier, checkVerifier,
  wrapKeystoreSecret, unwrapKeystoreSecret,
} from "./unlock.js";

let _wasmNs = null;
async function ensureWasm() {
  if (_wasmNs === null) _wasmNs = await loadTnWasm();
  return _wasmNs;
}

function hex(buf) { const a = buf instanceof Uint8Array ? buf : new Uint8Array(buf); return Array.from(a).map((b) => b.toString(16).padStart(2, "0")).join(""); }

// ---------------------------------------------------------------------------
// In-memory unlocked state
// ---------------------------------------------------------------------------

/** @type {Map<string, { label: string, kits: Map<string, Uint8Array[]> }>} */
const unlocked = new Map();

/** @type {CryptoKey | null} */
let emk = null;

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

// Treat any keystore entry without an explicit `source` as a vault
// import — that's how every entry written before session 13 looked.
function keystoreSource(k) {
  return k.source || "vault";
}

async function readStore() {
  const out = await chrome.storage.local.get(["keystores", "order"]);
  // Back-compat: earlier single-keystore builds wrote keystore_blob.
  // Promote it to a default entry on first read.
  if (!out.keystores) {
    const legacy = (await chrome.storage.local.get(["keystore_blob"])).keystore_blob;
    if (legacy) {
      const id = "ks_" + Math.random().toString(36).slice(2, 10);
      const migrated = [{ id, label: "Legacy keystore", added_at: new Date().toISOString(), source: "vault", blob: legacy }];
      await chrome.storage.local.set({ keystores: migrated, order: [id] });
      await chrome.storage.local.remove("keystore_blob");
      return { keystores: migrated, order: [id] };
    }
    return { keystores: [], order: [] };
  }
  return { keystores: out.keystores, order: out.order || out.keystores.map((k) => k.id) };
}

async function writeStore({ keystores, order }) {
  await chrome.storage.local.set({ keystores, order });
}

async function readExtensionUnlock() {
  const out = await chrome.storage.local.get(["extension_unlock"]);
  return out.extension_unlock || null;
}

async function writeExtensionUnlock(eu) {
  if (eu) await chrome.storage.local.set({ extension_unlock: eu });
  else await chrome.storage.local.remove("extension_unlock");
}

function genId() {
  return "ks_" + Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-4);
}

async function addKeystore({ label, blob, secretForEmk }) {
  const { keystores, order } = await readStore();
  const id = genId();
  const entry = { id, label: label || "Keystore", added_at: new Date().toISOString(), source: "vault", blob };
  // If extension unlock is set up AND we are currently unlocked,
  // bind this keystore to the EMK on the way in so the user never
  // has to type the per-keystore passphrase again.
  if (emk && secretForEmk) {
    try {
      entry.emk_wrapped_secret = await wrapKeystoreSecret(emk, secretForEmk);
    } catch {
      // Non-fatal: keystore still works via passphrase.
    }
  }
  const nextStores = [...keystores, entry];
  const nextOrder = [...order, id];
  await writeStore({ keystores: nextStores, order: nextOrder });
  return { ok: true, id, label: entry.label };
}

// Local-file imports skip passphrase encryption entirely. The bundle
// is stored plaintext under chrome.storage.local — the source file is
// already sitting plaintext on the user's filesystem, so wrapping it
// here is theatre. We auto-load it into memory immediately so the
// popup shows the keystore as ready without an unlock step.
async function addLocalFileKeystore({ label, filename, bundle }) {
  await ensureWasm();
  if (!bundle || !bundle.files || typeof bundle.files !== "object") {
    return { ok: false, reason: "bundle missing files map" };
  }
  const { keystores, order } = await readStore();
  const id = genId();
  const entry = {
    id,
    label: label || filename || "Keystore",
    added_at: new Date().toISOString(),
    source: "local-file",
    filename: filename || null,
    bundle,
  };
  const nextStores = [...keystores, entry];
  const nextOrder = [...order, id];
  await writeStore({ keystores: nextStores, order: nextOrder });
  // Load right away so the keystore is usable on the very next page
  // scan with no further user action.
  const loaded = await loadBundleIntoMemory(id, entry.label, bundle);
  return { ok: true, id, label: entry.label, loaded };
}

// Add a kit received from the vault pair page. One row per group per
// project (so the popup can list them individually and the user can
// remove just one project's kits without touching local-file imports).
//
// Security (O-9 resolution):
//   - The vault's AWK never reaches the extension. The pair page
//     decrypted the project body in the user's signed-in tab (D-1
//     vault-passive, D-2 browser-as-peer) and only forwarded the
//     resulting per-group kits.
//   - The kit IS the bearer credential for its group; encrypting the
//     copy held by the extension adds nothing (matches Session 13's
//     local-file rationale).
//   - externally_connectable in manifest.json gates which origins can
//     even reach this codepath.
async function addVaultPairedKit({
  project_id, project_label, group, kit_b64, state_b64,
  account_label, paired_at,
}) {
  await ensureWasm();
  if (!project_id || !group || !kit_b64) {
    return { ok: false, reason: "missing project_id / group / kit_b64" };
  }
  // Build a minimal bundle that loadBundleIntoMemory can consume.
  // bundle.files is keyed by virtual path so kit + state look like the
  // body/<group>.btn.mykit shape every other path expects.
  const files = {};
  files[`body/${group}.btn.mykit`] = kit_b64;
  if (state_b64) files[`body/${group}.btn.state`] = state_b64;
  const bundle = { files };
  const { keystores, order } = await readStore();
  // De-dupe: if the same (project_id, group) is already paired, replace
  // it in place so re-pair behaves like "refresh".
  const dupIdx = keystores.findIndex(
    (k) => keystoreSource(k) === "vault-paired" &&
           k.project_id === project_id && k.group === group,
  );
  let id;
  let nextStores;
  let nextOrder;
  const label = `${project_label || project_id} · ${group}`;
  if (dupIdx >= 0) {
    id = keystores[dupIdx].id;
    nextStores = keystores.map((k, i) => i === dupIdx ? {
      ...k, label, bundle, paired_at, account_label,
    } : k);
    nextOrder = order;
    unlocked.delete(id);
  } else {
    id = genId();
    const entry = {
      id,
      label,
      added_at: new Date().toISOString(),
      source: "vault-paired",
      project_id,
      project_label: project_label || null,
      group,
      account_label: account_label || null,
      paired_at: paired_at || new Date().toISOString(),
      bundle,
    };
    nextStores = [...keystores, entry];
    nextOrder = [...order, id];
  }
  await writeStore({ keystores: nextStores, order: nextOrder });
  const loaded = await loadBundleIntoMemory(id, label, bundle);
  return { ok: true, id, label, replaced: dupIdx >= 0, loaded };
}

async function removeKeystore(id) {
  const { keystores, order } = await readStore();
  const nextStores = keystores.filter((k) => k.id !== id);
  const nextOrder = order.filter((k) => k !== id);
  await writeStore({ keystores: nextStores, order: nextOrder });
  unlocked.delete(id);
  return { ok: true };
}

async function renameKeystore(id, label) {
  const { keystores, order } = await readStore();
  const nextStores = keystores.map((k) => (k.id === id ? { ...k, label } : k));
  await writeStore({ keystores: nextStores, order });
  const u = unlocked.get(id);
  if (u) u.label = label;
  return { ok: true };
}

async function reorderKeystores(newOrder) {
  const { keystores } = await readStore();
  const allIds = new Set(keystores.map((k) => k.id));
  const cleaned = newOrder.filter((id) => allIds.has(id));
  for (const k of keystores) if (!cleaned.includes(k.id)) cleaned.push(k.id);
  await writeStore({ keystores, order: cleaned });
  return { ok: true, order: cleaned };
}

// ---------------------------------------------------------------------------
// Per-keystore unlock (legacy path; still supported as the fallback
// inside the extension-wide unlock flow).
// ---------------------------------------------------------------------------

async function deriveAesKey(passphrase, saltBytes, iterations) {
  const pk = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(passphrase),
    { name: "PBKDF2" }, false, ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    pk, { name: "AES-GCM", length: 256 }, false, ["decrypt"],
  );
}

async function decryptKeystoreBlob(blob, passphrase) {
  const iterations = (blob.kdf_params && blob.kdf_params.iterations) || 260000;
  const key = await deriveAesKey(passphrase, b64ToBytes(blob.salt_b64), iterations);
  const pt = new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBytes(blob.nonce_b64) }, key, b64ToBytes(blob.ciphertext_b64),
  ));
  return JSON.parse(new TextDecoder().decode(pt));
}

async function loadBundleIntoMemory(id, label, bundle) {
  if (!bundle || !bundle.files) {
    console.error(`[ext:unlock] loadBundleIntoMemory(${id}): bundle invalid`);
    return { ok: false, reason: "bundle invalid" };
  }
  const ns = await ensureWasm();
  const kits = new Map();
  let skipped = 0;
  for (const [name, valB64] of Object.entries(bundle.files)) {
    if (!/\.btn\.(mykit|mykit\.revoked\.\d+)$/.test(name)) continue;
    const kitBytes = b64ToBytes(valB64);
    let pubId;
    try { pubId = hex(ns.btnKitPublisherId(kitBytes)); }
    catch (e) {
      skipped += 1;
      console.error(`[ext:unlock] loadBundleIntoMemory(${id}): rejected kit ${name} (${e?.name || "Error"} ${e?.message || ""})`);
      continue;
    }
    const list = kits.get(pubId) || [];
    list.push(kitBytes);
    kits.set(pubId, list);
  }
  unlocked.set(id, { label, kits });
  const kitCount = Array.from(kits.values()).reduce((n, list) => n + list.length, 0);
  console.log(`[ext:unlock] loaded id=${id} label=${JSON.stringify(label)} publishers=${kits.size} kits=${kitCount}${skipped ? ` skipped=${skipped}` : ""}`);
  return { ok: true, id, label, publishers: kits.size, kit_count: kitCount };
}

async function unlockOne(id, passphrase) {
  await ensureWasm();
  const { keystores } = await readStore();
  const entry = keystores.find((k) => k.id === id);
  if (!entry) {
    console.error(`[ext:unlock] unlockOne(${id}): keystore not found`);
    return { ok: false, reason: "keystore not found" };
  }
  console.log(`[ext:unlock] unlockOne id=${id} source=${keystoreSource(entry)}`);
  // Local-file keystores have no passphrase. Just (re)load the
  // plaintext bundle if it isn't already in memory.
  if (keystoreSource(entry) === "local-file") {
    if (!entry.bundle) return { ok: false, reason: "local-file entry missing bundle" };
    return loadBundleIntoMemory(entry.id, entry.label, entry.bundle);
  }
  let bundle;
  try {
    bundle = await decryptKeystoreBlob(entry.blob, passphrase);
  } catch (e) {
    console.error(`[ext:unlock] unlockOne(${id}): wrong passphrase (${e?.name || "Error"})`);
    return { ok: false, reason: "wrong passphrase" };
  }
  const res = await loadBundleIntoMemory(entry.id, entry.label, bundle);
  // If the user is unlocking with a passphrase while the extension
  // is also unlocked under an EMK, bind this keystore now so future
  // unlocks come for free.
  if (res.ok && emk && !entry.emk_wrapped_secret) {
    try {
      const wrapped = await wrapKeystoreSecret(emk, passphrase);
      const { keystores: ks2, order: ord2 } = await readStore();
      const updated = ks2.map((k) => (k.id === id ? { ...k, emk_wrapped_secret: wrapped } : k));
      await writeStore({ keystores: updated, order: ord2 });
    } catch {
      // Non-fatal.
    }
  }
  return res;
}

async function lockOne(id) {
  unlocked.delete(id);
  return { ok: true };
}

async function lockAll() {
  unlocked.clear();
  emk = null;
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Extension-wide unlock (passkey-PRF, with passphrase fallback).
//
// The popup runs the WebAuthn / passphrase flow, derives the EMK
// material in its own page context, then sends it here. The service
// worker:
//   - on setup: stores the verifier + the credential metadata, and
//     binds every currently-unlocked keystore to the EMK.
//   - on unlock: receives the freshly-derived EMK material, checks
//     the verifier, then walks every keystore that has an
//     emk_wrapped_secret, unwraps the secret, decrypts the blob, and
//     loads the bundle.
// ---------------------------------------------------------------------------

async function importEmkFromTransport(emkRawB64) {
  return importEmk(b64ToBytes(emkRawB64));
}

// Set up extension-wide unlock for the first time.
//
// Args:
//   kind: "prf" | "passphrase"
//   emk_raw_b64: 32 bytes of the freshly-derived EMK
//   prf:   { credential_id_b64, prf_salt_b64, rp_id }   (kind="prf")
//   pass:  { kdf_salt_b64, kdf_iterations }            (kind="passphrase")
//   keystore_secrets: { [keystore_id]: passphraseString }
//     Optional. Any keystore listed here is bound to the EMK now so
//     subsequent unlocks don't need its passphrase.
async function setupExtensionUnlock({ kind, emk_raw_b64, prf, pass, keystore_secrets }) {
  if (kind !== "prf" && kind !== "passphrase") return { ok: false, reason: "bad kind" };
  const newEmk = await importEmkFromTransport(emk_raw_b64);
  const verifier = await makeVerifier(newEmk);
  const eu = { kind, verifier };
  if (kind === "prf") {
    if (!prf || !prf.credential_id_b64 || !prf.prf_salt_b64) return { ok: false, reason: "missing prf metadata" };
    eu.credential_id_b64 = prf.credential_id_b64;
    eu.prf_salt_b64 = prf.prf_salt_b64;
    eu.rp_id = prf.rp_id || "tn-decrypt-extension";
  } else {
    if (!pass || !pass.kdf_salt_b64 || !pass.kdf_iterations) return { ok: false, reason: "missing kdf metadata" };
    eu.kdf_salt_b64 = pass.kdf_salt_b64;
    eu.kdf_iterations = pass.kdf_iterations;
  }
  await writeExtensionUnlock(eu);
  emk = newEmk;

  // Bind any keystore secrets the popup gave us. This is the path
  // where the user has unlocked some keystores already and wants to
  // promote them so they unlock with the passkey tap from now on.
  let bound = 0;
  if (keystore_secrets && typeof keystore_secrets === "object") {
    const { keystores, order } = await readStore();
    const updated = await Promise.all(keystores.map(async (k) => {
      const secret = keystore_secrets[k.id];
      if (!secret) return k;
      try {
        const w = await wrapKeystoreSecret(newEmk, secret);
        bound += 1;
        return { ...k, emk_wrapped_secret: w };
      } catch {
        return k;
      }
    }));
    await writeStore({ keystores: updated, order });
  }
  return { ok: true, kind, bound };
}

// Unlock the extension with material the popup just derived.
async function unlockExtension({ emk_raw_b64 }) {
  await ensureWasm();
  const eu = await readExtensionUnlock();
  if (!eu) {
    console.error("[ext:unlock] unlockExtension: not configured");
    return { ok: false, reason: "extension unlock not configured" };
  }
  console.log(`[ext:unlock] unlockExtension kind=${eu.kind}`);
  const candidate = await importEmkFromTransport(emk_raw_b64);
  const ok = await checkVerifier(candidate, eu.verifier);
  if (!ok) {
    console.error("[ext:unlock] unlockExtension: verifier mismatch (wrong PRF / passphrase)");
    return { ok: false, reason: "verifier mismatch" };
  }
  emk = candidate;

  // Walk every keystore with an emk_wrapped_secret and unlock it.
  const { keystores } = await readStore();
  let unlockedCount = 0;
  const errors = [];
  for (const k of keystores) {
    if (!k.emk_wrapped_secret) continue;
    try {
      const passphrase = await unwrapKeystoreSecret(emk, k.emk_wrapped_secret);
      const bundle = await decryptKeystoreBlob(k.blob, passphrase);
      const res = await loadBundleIntoMemory(k.id, k.label, bundle);
      if (res.ok) unlockedCount += 1;
    } catch (e) {
      const reason = e && e.message ? e.message : String(e);
      console.error(`[ext:unlock] unlockExtension: keystore ${k.id} (${k.label}) failed: ${e?.name || "Error"} ${reason}`);
      errors.push({ id: k.id, label: k.label, reason });
    }
  }
  console.log(`[ext:unlock] unlockExtension done unlocked=${unlockedCount} errors=${errors.length}`);
  return { ok: true, unlocked: unlockedCount, errors };
}

async function disableExtensionUnlock() {
  await writeExtensionUnlock(null);
  // Also strip emk_wrapped_secret off every keystore so the on-disk
  // state matches the user's intent.
  const { keystores, order } = await readStore();
  const stripped = keystores.map((k) => {
    if (!k.emk_wrapped_secret) return k;
    const { emk_wrapped_secret, ...rest } = k;
    return rest;
  });
  await writeStore({ keystores: stripped, order });
  emk = null;
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

// Walk every plaintext-bundle keystore (local-file OR vault-paired)
// and load it into memory. Called at service-worker startup so these
// keystores are immediately usable without any unlock UI. Vault-paired
// kits are stored plaintext for the same reason local-file imports are
// (the kit IS the bearer credential — wrapping it adds nothing; O-9).
async function autoLoadLocalFileKeystores() {
  await ensureWasm();
  const { keystores } = await readStore();
  let count = 0;
  for (const k of keystores) {
    const src = keystoreSource(k);
    if (src !== "local-file" && src !== "vault-paired") continue;
    if (unlocked.has(k.id)) continue;
    if (!k.bundle) continue;
    try {
      const r = await loadBundleIntoMemory(k.id, k.label, k.bundle);
      if (r.ok) count += 1;
    } catch {
      // skip; the entry will simply appear as not-loaded in status().
    }
  }
  return count;
}

async function status() {
  const { keystores, order } = await readStore();
  const eu = await readExtensionUnlock();
  // Make sure plaintext-on-disk keystores are loaded before reporting
  // status. Cheap if everything's already in memory.
  await autoLoadLocalFileKeystores();
  return {
    unlocked: unlocked.size > 0,
    order,
    extension_unlock: eu ? {
      configured: true,
      kind: eu.kind,
      session_unlocked: !!emk,
    } : { configured: false, kind: null, session_unlocked: false },
    keystores: keystores.map((k) => {
      const u = unlocked.get(k.id);
      const pubCount = u ? u.kits.size : 0;
      const kitCount = u ? Array.from(u.kits.values()).reduce((n, l) => n + l.length, 0) : 0;
      const source = keystoreSource(k);
      return {
        id: k.id, label: k.label, added_at: k.added_at,
        source,
        filename: k.filename || null,
        // Vault-paired-only fields (null on other sources). Lets the
        // popup group rows by project / show "paired with <email>".
        project_id: k.project_id || null,
        project_label: k.project_label || null,
        group: k.group || null,
        account_label: k.account_label || null,
        paired_at: k.paired_at || null,
        unlocked: !!u, publisher_count: pubCount, kit_count: kitCount,
        bound_to_emk: !!k.emk_wrapped_secret,
        // Local-file AND vault-paired entries are plaintext bundles —
        // nothing to unlock. UI should not show a passphrase prompt.
        requires_unlock: source !== "local-file" && source !== "vault-paired",
      };
    }),
  };
}

// ---------------------------------------------------------------------------
// Classify one candidate. Tries each unlocked keystore in `order`.
// Returns {class, ...} per the content-script contract.
// ---------------------------------------------------------------------------

async function classifyOne(b64s, orderCache, ns) {
  if (!ns) ns = await ensureWasm();
  let ctBytes;
  try { ctBytes = b64ToBytes(b64s); } catch { return { class: "not-tn" }; }
  let pubId;
  try { pubId = hex(ns.btnCiphertextPublisherId(ctBytes)); }
  catch { return { class: "not-tn" }; }

  const resolution = orderCache || (await readStore()).order;
  for (const id of resolution) {
    const u = unlocked.get(id);
    if (!u) continue;
    const kits = u.kits.get(pubId);
    if (!kits || kits.length === 0) continue;
    for (const kit of kits) {
      try {
        const pt = ns.btnDecrypt(kit, ctBytes);
        let json = null;
        try { json = JSON.parse(new TextDecoder().decode(pt)); } catch {}
        const leaf = Number(ns.btnKitLeaf(kit));
        console.log(`[ext:decrypt] hit publisher=${pubId.slice(0, 12)} keystore=${id} leaf=${leaf} bytes=${pt.length}`);
        return {
          class: "decrypted",
          plaintext_b64: bytesToB64(pt),
          plaintext_utf8: json === null ? new TextDecoder().decode(pt) : null,
          plaintext_json: json,
          publisher_id_hex: pubId,
          kit_leaf: leaf,
          keystore_label: u.label,
        };
      } catch {
        // try next kit / next keystore
      }
    }
  }
  return { class: "sealed", publisher_id_hex: pubId };
}

// ---------------------------------------------------------------------------
// Manual paste-and-decrypt path used by the popup's "Decrypt a TN
// ciphertext" card. Mirrors the dashboard widget at
// tnproto-org/static/account/decrypt.js (D-1, D-22) — same wasm
// primitive, same kit shape — but swept across every loaded kit so
// the user doesn't have to pick a group.
//
// Input: ciphertext_b64 — accepts base64 (with or without padding,
// URL-safe variants tolerated) OR hex (whitespace/colons stripped).
// Output (success): {ok, plaintext_b64, plaintext_utf8, keystore_label, group}.
// Output (failure): {ok:false, reason}.
// ---------------------------------------------------------------------------
function parsePastedCiphertext(text) {
  const raw = (text || "").trim();
  if (!raw) return null;
  // Hex first: if the input (whitespace/colons stripped) is purely
  // hex digits and has an even length, treat it as hex. Hex chars are
  // a strict subset of base64, so the b64 regex would also match —
  // but base64 decoding hex would silently produce wrong bytes.
  const hexs = raw.replace(/[\s:]+/g, "");
  if (/^[0-9a-fA-F]+$/.test(hexs) && hexs.length % 2 === 0 && hexs.length > 0) {
    const out = new Uint8Array(hexs.length / 2);
    for (let i = 0; i < out.length; i += 1) {
      out[i] = parseInt(hexs.slice(i * 2, i * 2 + 2), 16);
    }
    return { bytes: out, format: "hex" };
  }
  // Base64 attempt: tolerate URL-safe variants and missing padding.
  try {
    const cleaned = raw.replace(/\s+/g, "");
    if (/^[A-Za-z0-9_+/=-]+$/.test(cleaned) && cleaned.length >= 4) {
      const norm = cleaned.replace(/-/g, "+").replace(/_/g, "/");
      const padded = norm + "=".repeat((4 - norm.length % 4) % 4);
      const out = b64ToBytes(padded);
      if (out.length > 0) return { bytes: out, format: "b64" };
    }
  } catch { /* fall through */ }
  return null;
}

// Try to decode bytes as printable UTF-8. Returns null if the bytes
// hold control characters that would render as garbage.
function tryUtf8(bytes) {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x08\x0e-\x1f]/.test(text)) return null;
    return text;
  } catch {
    return null;
  }
}

// Look up the group (vault-paired) or filename (local-file) for a
// keystore id, so the popup can show a useful "matched" hint.
async function lookupKeystoreGroup(id) {
  try {
    const { keystores } = await readStore();
    const entry = keystores.find((k) => k.id === id);
    if (!entry) return null;
    if (entry.group) return entry.group;
    if (entry.filename) return entry.filename;
    return null;
  } catch {
    return null;
  }
}

async function popupDecrypt({ ciphertext_b64 }) {
  const t0 = Date.now();
  const ns = await ensureWasm();

  const parsed = parsePastedCiphertext(ciphertext_b64);
  if (!parsed) {
    console.log("[ext:popup-decrypt] parse failed (input is neither base64 nor hex)");
    return { ok: false, reason: "input is neither base64 nor hex" };
  }
  console.log(`[ext:popup-decrypt] parsed format=${parsed.format} bytes=${parsed.bytes.length}`);

  if (unlocked.size === 0) {
    console.log("[ext:popup-decrypt] no kits loaded — import or pair first");
    return { ok: false, reason: "no kits loaded — import or pair first" };
  }

  let totalKitsTried = 0;
  const errorsByKeystore = [];
  for (const [id, ks] of unlocked.entries()) {
    for (const [pubId, kits] of ks.kits.entries()) {
      for (const kit of kits) {
        totalKitsTried += 1;
        try {
          const pt = ns.btnDecrypt(kit, parsed.bytes);
          const utf8 = tryUtf8(pt);
          const group = await lookupKeystoreGroup(id);
          const dt = Date.now() - t0;
          console.log(`[ext:popup-decrypt] hit keystore=${id} label=${JSON.stringify(ks.label)} publisher=${pubId.slice(0, 12)} pt_bytes=${pt.length} utf8=${utf8 !== null} dt=${dt}ms tried=${totalKitsTried}`);
          return {
            ok: true,
            plaintext_b64: bytesToB64(pt),
            plaintext_utf8: utf8,
            keystore_id: id,
            keystore_label: ks.label,
            group: group,
            publisher_id_hex: pubId,
            kits_tried: totalKitsTried,
            dt_ms: dt,
          };
        } catch (e) {
          // Per-kit failures are noisy by design (most kits won't
          // match a given ciphertext); only log at debug level.
          console.debug(`[ext:popup-decrypt] miss keystore=${id} pub=${pubId.slice(0, 12)} err=${e?.name || "Error"}`);
        }
      }
    }
  }
  const dt = Date.now() - t0;
  console.log(`[ext:popup-decrypt] no kit matched tried=${totalKitsTried} dt=${dt}ms errors=${errorsByKeystore.length}`);
  return { ok: false, reason: "no kit matched", kits_tried: totalKitsTried, dt_ms: dt };
}

async function classifyBatch(candidates) {
  const t0 = Date.now();
  const ns = await ensureWasm();
  const { order } = await readStore();
  const out = [];
  for (const c of candidates) out.push(await classifyOne(c, order, ns));
  const tally = { decrypted: 0, sealed: 0, "not-tn": 0 };
  for (const r of out) tally[r.class] = (tally[r.class] || 0) + 1;
  console.log(`[ext:decrypt] classifyBatch n=${candidates.length} decrypted=${tally.decrypted} sealed=${tally.sealed} not-tn=${tally["not-tn"]} dt=${Date.now() - t0}ms`);
  return { ok: true, results: out };
}

// ---------------------------------------------------------------------------
// Message dispatch
// ---------------------------------------------------------------------------

// Service-worker boot: auto-load every local-file keystore so they
// are usable on first content-script call without going through the
// popup. Best-effort — if it fails, the next status() call will retry.
console.log("[ext] service worker booting (D-22 unlock + D-21 per-keystore + Session 13 local-file + O-9 vault-paired)");
(async () => {
  try {
    const n = await autoLoadLocalFileKeystores();
    console.log(`[ext] boot: auto-loaded ${n} local-file keystore(s)`);
  } catch (e) {
    console.error(`[ext] boot: autoLoadLocalFileKeystores failed: ${e?.name || "Error"} ${e?.message || ""}`);
  }
})();

// ---------------------------------------------------------------------------
// External message dispatch — the vault's /extension-pair page posts
// kits here over chrome.runtime.sendMessage(<extension_id>, ...). The
// origin allowlist in manifest.externally_connectable is the manifest
// gate; we re-check sender.url here as defense-in-depth (O-9, D-1).
// ---------------------------------------------------------------------------
const EXT_PAIR_ALLOWED_ORIGINS = [
  "http://localhost:8790",
  "https://tnproto.org",
];

function senderOriginOk(sender) {
  const url = sender && sender.url;
  if (!url) return false;
  try {
    const u = new URL(url);
    const origin = `${u.protocol}//${u.host}`;
    return EXT_PAIR_ALLOWED_ORIGINS.includes(origin);
  } catch {
    return false;
  }
}

chrome.runtime.onMessageExternal.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (!senderOriginOk(sender)) {
        console.error(`[ext:vault-pair] rejecting external sender url=${sender && sender.url}`);
        return sendResponse({ ok: false, reason: "sender origin not allowed" });
      }
      if (!msg || msg.type !== "tn:vault-pair") {
        return sendResponse({ ok: false, reason: "unknown external message" });
      }
      const kits = Array.isArray(msg.kits) ? msg.kits : [];
      console.log(`[ext:vault-pair] received pair from ${sender.url} kits=${kits.length} account=${msg.account_label || "?"}`);
      let added = 0;
      const errors = [];
      for (const k of kits) {
        try {
          const r = await addVaultPairedKit({
            project_id: k.project_id,
            project_label: k.project_label,
            group: k.group,
            kit_b64: k.kit_bytes_b64 || k.kit_b64,
            state_b64: k.state_bytes_b64 || k.state_b64,
            account_label: msg.account_label,
            paired_at: msg.paired_at,
          });
          if (r.ok) added += 1;
          else errors.push({ project_id: k.project_id, group: k.group, reason: r.reason });
        } catch (e) {
          errors.push({ project_id: k.project_id, group: k.group, reason: e?.message || String(e) });
        }
      }
      console.log(`[ext:vault-pair] stored kits=${added} errors=${errors.length}`);
      sendResponse({ ok: true, count: added, errors });
    } catch (e) {
      console.error(`[ext:vault-pair] fatal: ${e?.name || "Error"} ${e?.message || ""}`);
      sendResponse({ ok: false, reason: e?.message || String(e) });
    }
  })();
  return true;
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      switch (msg.type) {
        case "status":              return sendResponse(await status());
        case "addKeystore":         return sendResponse(await addKeystore(msg));
        case "addLocalFileKeystore":return sendResponse(await addLocalFileKeystore(msg));
        case "addVaultPairedKit":   return sendResponse(await addVaultPairedKit(msg));
        case "removeKeystore":      return sendResponse(await removeKeystore(msg.id));
        case "renameKeystore":      return sendResponse(await renameKeystore(msg.id, msg.label));
        case "reorderKeystores":    return sendResponse(await reorderKeystores(msg.order));
        case "unlock":              return sendResponse(await unlockOne(msg.id, msg.passphrase));
        case "lock":                return sendResponse(await lockOne(msg.id));
        case "lockAll":             return sendResponse(await lockAll());
        case "classifyBatch":       return sendResponse(await classifyBatch(msg.candidates));
        case "tn:popup-decrypt":    return sendResponse(await popupDecrypt(msg));
        // Extension-wide unlock plumbing
        case "setupExtensionUnlock":   return sendResponse(await setupExtensionUnlock(msg));
        case "unlockExtension":        return sendResponse(await unlockExtension(msg));
        case "disableExtensionUnlock": return sendResponse(await disableExtensionUnlock());
        case "getExtensionUnlockMeta": {
          const eu = await readExtensionUnlock();
          if (!eu) return sendResponse({ ok: true, configured: false });
          return sendResponse({
            ok: true,
            configured: true,
            kind: eu.kind,
            credential_id_b64: eu.credential_id_b64 || null,
            prf_salt_b64: eu.prf_salt_b64 || null,
            rp_id: eu.rp_id || null,
            kdf_salt_b64: eu.kdf_salt_b64 || null,
            kdf_iterations: eu.kdf_iterations || null,
          });
        }
        // Back-compat shims (old popup / options builds):
        case "saveKeystore":     return sendResponse(await addKeystore({ label: msg.label || "Imported", blob: msg.blob }));
        case "clearKeystore":    return sendResponse({ ok: true, note: "use removeKeystore(id) in multi-keystore mode" });
        case "decrypt":          return sendResponse(await classifyOne(msg.ciphertext_b64));
        default:                 return sendResponse({ ok: false, reason: "unknown message " + msg.type });
      }
    } catch (e) {
      const reason = e && e.message ? e.message : String(e);
      console.error(`[ext] dispatch ${msg && msg.type}: ${e?.name || "Error"} ${reason}`);
      sendResponse({ ok: false, reason });
    }
  })();
  return true;
});
