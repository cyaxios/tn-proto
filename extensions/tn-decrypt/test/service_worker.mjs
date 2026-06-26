// Characterization tests for the REAL background.js service worker,
// driven through the chrome stub in harness.mjs. These pin the behavior
// the extension ships TODAY (storage migration, message dispatch, the
// externally_connectable origin gate, classify/decrypt, and the
// extension-wide EMK unlock flow) so the upcoming activeTab refactor has
// a safety net.

import {
  loadBackground, makeAsserter, makePublisher, makeVaultBlob,
  deriveEmkRaw, bytesToB64,
} from "./harness.mjs";
import { webcrypto } from "node:crypto";

const t = makeAsserter();

// ── status() on an empty store ─────────────────────────────────────────
{
  const { send } = await loadBackground();
  const st = await send({ type: "status" });
  t.truthy("status: empty store returns keystores array", Array.isArray(st.keystores));
  t.eq("status: empty store is locked", st.unlocked, false);
  t.eq("status: no extension unlock configured", st.extension_unlock.configured, false);
}

// ── legacy keystore_blob migration (pre-session-13 single-keystore) ─────
{
  const legacyBlob = { salt_b64: "x", nonce_b64: "y", ciphertext_b64: "z" };
  const { send, getStore } = await loadBackground({ seedStore: { keystore_blob: legacyBlob } });
  const st = await send({ type: "status" });
  t.eq("migration: legacy blob promoted to one keystore", st.keystores.length, 1);
  t.eq("migration: promoted entry is a vault source", st.keystores[0].source, "vault");
  t.truthy("migration: keystore_blob key removed", !("keystore_blob" in getStore()));
  t.truthy("migration: order references the new id", st.order.length === 1 && st.order[0] === st.keystores[0].id);
}

// ── addLocalFileKeystore: plaintext, auto-loaded, no unlock needed ──────
{
  const { send, wasm } = await loadBackground();
  const A = makePublisher(wasm, 13);
  const bundle = { version: "keystore-v1", files: { "alice.btn.mykit": A.kitB64 } };
  const res = await send({ type: "addLocalFileKeystore", label: "Alice", filename: "alice.tnpkg", bundle });
  t.truthy("local-file: add succeeds", res.ok);
  t.truthy("local-file: kit loaded on add", res.loaded && res.loaded.kit_count === 1);
  const st = await send({ type: "status" });
  const row = st.keystores.find((k) => k.id === res.id);
  t.eq("local-file: source is local-file", row.source, "local-file");
  t.eq("local-file: reports unlocked", row.unlocked, true);
  t.eq("local-file: requires_unlock is false", row.requires_unlock, false);
  t.eq("local-file: status flips to unlocked", st.unlocked, true);
  A.free();
}

// ── addLocalFileKeystore rejects a bundle with no files map ─────────────
{
  const { send } = await loadBackground();
  const res = await send({ type: "addLocalFileKeystore", label: "bad", bundle: { nope: 1 } });
  t.eq("local-file: bundle without files map rejected", res.ok, false);
}

// ── classifyBatch: decrypted / sealed / not-tn over real ciphertexts ────
{
  const { send, wasm } = await loadBackground();
  const A = makePublisher(wasm, 21);
  const B = makePublisher(wasm, 99);
  await send({
    type: "addLocalFileKeystore", label: "A", filename: "a.tnpkg",
    bundle: { files: { "a.btn.mykit": A.kitB64 } },
  });
  const ctA = A.encryptB64({ customer: "Alice", amount: 42 });
  const ctB = B.encryptB64({ customer: "Bob", amount: 7 });
  const noise = bytesToB64(new TextEncoder().encode(
    "this is just a long base64 blob that is definitely not a btn ciphertext at all",
  ));
  const res = await send({ type: "classifyBatch", candidates: [ctA, ctB, noise] });
  t.truthy("classify: batch ok", res.ok);
  t.eq("classify: A decrypts", res.results[0].class, "decrypted");
  t.eq("classify: A plaintext correct", res.results[0].plaintext_json?.customer, "Alice");
  t.eq("classify: B sealed (btn, no kit held)", res.results[1].class, "sealed");
  t.eq("classify: noise is not-tn", res.results[2].class, "not-tn");
  t.truthy("classify: B plaintext does NOT leak", res.results[1].plaintext_json == null);
  A.free(); B.free();
}

// ── popupDecrypt: hit / hex / bad-input / no-kit / no-kits-loaded ───────
{
  const { send, wasm } = await loadBackground();
  const A = makePublisher(wasm, 33);

  // no kits loaded yet
  const empty = await send({ type: "tn:popup-decrypt", ciphertext_b64: A.encryptB64({ x: 1 }) });
  t.truthy("popup: no kits loaded hint", !empty.ok && /no kits loaded/.test(empty.reason));

  await send({
    type: "addLocalFileKeystore", label: "A", filename: "a.tnpkg",
    bundle: { files: { "a.btn.mykit": A.kitB64 } },
  });
  const ctA = A.encryptB64({ customer: "Alice" });
  const hit = await send({ type: "tn:popup-decrypt", ciphertext_b64: ctA });
  t.truthy("popup: b64 hit", hit.ok && /Alice/.test(hit.plaintext_utf8 || ""));

  // hex form of the same ciphertext
  const ctBytes = Uint8Array.from(atob(ctA), (c) => c.charCodeAt(0));
  const hexStr = Array.from(ctBytes).map((b) => b.toString(16).padStart(2, "0")).join(" ");
  const hexHit = await send({ type: "tn:popup-decrypt", ciphertext_b64: hexStr });
  t.truthy("popup: hex input decrypts", hexHit.ok);

  const bad = await send({ type: "tn:popup-decrypt", ciphertext_b64: "!!!not b64 or hex!!!" });
  t.truthy("popup: bad input rejected pre-flight", !bad.ok && /neither base64 nor hex/.test(bad.reason));

  const B = makePublisher(wasm, 88);
  const noMatch = await send({ type: "tn:popup-decrypt", ciphertext_b64: B.encryptB64({ y: 2 }) });
  t.truthy("popup: unknown publisher -> no kit matched", !noMatch.ok && /no kit matched/.test(noMatch.reason));
  A.free(); B.free();
}

// ── externally_connectable origin gate (senderOriginOk) ────────────────
{
  const { send, sendExternal, wasm } = await loadBackground();
  const P = makePublisher(wasm, 44);
  const pairMsg = {
    type: "tn:vault-pair",
    account_label: "gil@cyaxios.com",
    kits: [{ project_id: "proj1", project_label: "Orders", group: "g1", kit_bytes_b64: P.kitB64 }],
  };

  // Allowed production origin
  const okRes = await sendExternal(pairMsg, "https://vault.tn-proto.org/extension-pair?ext_id=x");
  t.truthy("origin gate: vault.tn-proto.org accepted", okRes.ok && okRes.count === 1);

  // Disallowed origin must be rejected before any kit is stored
  const evil = await sendExternal(pairMsg, "https://evil.example.com/extension-pair");
  t.truthy("origin gate: foreign origin rejected", !evil.ok && /origin not allowed/.test(evil.reason));

  // A sender with no url at all is rejected
  const noUrl = await sendExternal(pairMsg, undefined);
  t.truthy("origin gate: missing sender url rejected", !noUrl.ok);

  // The paired kit is now usable for decrypt
  const ct = P.encryptB64({ note: "paired" });
  const dec = await send({ type: "classifyBatch", candidates: [ct] });
  t.eq("vault-pair: paired kit decrypts", dec.results[0].class, "decrypted");
  P.free();
}

// ── vault-pair dedup: re-pair same (project_id, group) replaces in place ─
{
  const { sendExternal, send, wasm } = await loadBackground();
  const P = makePublisher(wasm, 55);
  const mk = (label) => ({
    type: "tn:vault-pair", account_label: "gil",
    kits: [{ project_id: "p", project_label: label, group: "g", kit_bytes_b64: P.kitB64 }],
  });
  await sendExternal(mk("First"), "https://vault.tn-proto.org/x");
  await sendExternal(mk("Second"), "https://vault.tn-proto.org/x");
  const st = await send({ type: "status" });
  const paired = st.keystores.filter((k) => k.source === "vault-paired");
  t.eq("vault-pair dedup: still one row after re-pair", paired.length, 1);
  t.truthy("vault-pair dedup: label refreshed to latest", /Second/.test(paired[0].label));
  P.free();
}

// ── rename / reorder / remove ──────────────────────────────────────────
{
  const { send, wasm } = await loadBackground();
  const A = makePublisher(wasm, 61);
  const B = makePublisher(wasm, 62);
  const ra = await send({ type: "addLocalFileKeystore", label: "A", bundle: { files: { "a.btn.mykit": A.kitB64 } } });
  const rb = await send({ type: "addLocalFileKeystore", label: "B", bundle: { files: { "b.btn.mykit": B.kitB64 } } });

  await send({ type: "renameKeystore", id: ra.id, label: "Renamed-A" });
  let st = await send({ type: "status" });
  t.eq("rename: label updated", st.keystores.find((k) => k.id === ra.id).label, "Renamed-A");

  await send({ type: "reorderKeystores", order: [rb.id, ra.id] });
  st = await send({ type: "status" });
  t.eq("reorder: order applied", st.order[0], rb.id);

  await send({ type: "removeKeystore", id: ra.id });
  st = await send({ type: "status" });
  t.truthy("remove: keystore gone", !st.keystores.some((k) => k.id === ra.id));
  t.truthy("remove: order pruned", !st.order.includes(ra.id));
  A.free(); B.free();
}

// ── vault keystore: addKeystore(blob) + unlockOne(passphrase) ───────────
{
  const { send, wasm } = await loadBackground();
  const A = makePublisher(wasm, 71);
  const bundle = { version: "keystore-v1", files: { "a.btn.mykit": A.kitB64 } };
  const blob = await makeVaultBlob(bundle, "correct horse");
  const add = await send({ type: "addKeystore", label: "Vault A", blob });
  t.truthy("vault: addKeystore ok", add.ok);

  let st = await send({ type: "status" });
  const row = st.keystores.find((k) => k.id === add.id);
  t.eq("vault: starts locked", row.unlocked, false);
  t.eq("vault: requires unlock", row.requires_unlock, true);

  const wrong = await send({ type: "unlock", id: add.id, passphrase: "nope" });
  t.truthy("vault: wrong passphrase rejected", !wrong.ok && /wrong passphrase/.test(wrong.reason));

  const right = await send({ type: "unlock", id: add.id, passphrase: "correct horse" });
  t.truthy("vault: correct passphrase unlocks", right.ok && right.kit_count === 1);
  A.free();
}

// ── extension-wide EMK unlock: setup (bind) → lockAll → unlockExtension ──
{
  const { send, wasm } = await loadBackground();
  const A = makePublisher(wasm, 81);
  const passphrase = "vault-pass";
  const blob = await makeVaultBlob({ files: { "a.btn.mykit": A.kitB64 } }, passphrase);
  const add = await send({ type: "addKeystore", label: "Vault A", blob });

  // Popup derives EMK material from an extension passphrase, then setup
  // binds the keystore secret under the EMK.
  const extPass = "extension-master";
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const iterations = 260000;
  const emkRaw = await deriveEmkRaw(extPass, salt, iterations);
  const setup = await send({
    type: "setupExtensionUnlock", kind: "passphrase",
    emk_raw_b64: bytesToB64(emkRaw),
    pass: { kdf_salt_b64: bytesToB64(salt), kdf_iterations: iterations },
    keystore_secrets: { [add.id]: passphrase },
  });
  t.truthy("emk: setup ok, bound one keystore", setup.ok && setup.bound === 1);

  let st = await send({ type: "status" });
  t.eq("emk: configured after setup", st.extension_unlock.configured, true);
  t.eq("emk: keystore reports bound_to_emk", st.keystores.find((k) => k.id === add.id).bound_to_emk, true);

  await send({ type: "lockAll" });
  st = await send({ type: "status" });
  t.eq("emk: lockAll drops session", st.extension_unlock.session_unlocked, false);
  t.eq("emk: keystore locked again", st.keystores.find((k) => k.id === add.id).unlocked, false);

  // Re-derive the same EMK and unlock the extension; the bound keystore
  // should come back without its per-keystore passphrase.
  const emkRaw2 = await deriveEmkRaw(extPass, salt, iterations);
  const unlock = await send({ type: "unlockExtension", emk_raw_b64: bytesToB64(emkRaw2) });
  t.truthy("emk: unlockExtension restores bound keystore", unlock.ok && unlock.unlocked === 1);

  // A wrong EMK must fail the verifier and unlock nothing.
  await send({ type: "lockAll" });
  const wrongEmk = await deriveEmkRaw("not-the-pass", salt, iterations);
  const bad = await send({ type: "unlockExtension", emk_raw_b64: bytesToB64(wrongEmk) });
  t.truthy("emk: wrong EMK fails verifier", !bad.ok && /verifier mismatch/.test(bad.reason));
  A.free();
}

// ── external pair payload validation + caps (F2 hardening) ─────────────
{
  const { sendExternal, send, wasm } = await loadBackground();
  const P = makePublisher(wasm, 91);
  const ORIGIN = "https://vault.tn-proto.org/extension-pair";
  const goodKit = { project_id: "proj", project_label: "Orders", group: "g1", kit_bytes_b64: P.kitB64 };

  // empty / non-array kits
  const empty = await sendExternal({ type: "tn:vault-pair", kits: [] }, ORIGIN);
  t.truthy("validate: empty kits rejected", !empty.ok && /non-empty/.test(empty.reason));

  // too many kits
  const flood = await sendExternal(
    { type: "tn:vault-pair", kits: Array.from({ length: 300 }, () => goodKit) }, ORIGIN);
  t.truthy("validate: oversized kits array rejected", !flood.ok && /too many/.test(flood.reason));

  // bad group charset (path-traversal-ish)
  const badGroup = await sendExternal(
    { type: "tn:vault-pair", kits: [{ ...goodKit, group: "../../etc/passwd" }] }, ORIGIN);
  t.truthy("validate: bad group charset rejected", !badGroup.ok && /invalid pair payload/.test(badGroup.reason));

  // oversized kit bytes
  const huge = "A".repeat(64 * 1024 + 4);
  const bigKit = await sendExternal(
    { type: "tn:vault-pair", kits: [{ ...goodKit, kit_bytes_b64: huge }] }, ORIGIN);
  t.truthy("validate: oversized kit bytes rejected", !bigKit.ok);

  // missing project_id
  const noProj = await sendExternal(
    { type: "tn:vault-pair", kits: [{ group: "g1", kit_bytes_b64: P.kitB64 }] }, ORIGIN);
  t.truthy("validate: missing project_id rejected", !noProj.ok);

  // a valid payload still goes through unchanged
  const ok = await sendExternal({ type: "tn:vault-pair", account_label: "gil", kits: [goodKit] }, ORIGIN);
  t.truthy("validate: well-formed payload still accepted", ok.ok && ok.count === 1);

  // nothing from the rejected messages was persisted
  const st = await send({ type: "status" });
  const paired = st.keystores.filter((k) => k.source === "vault-paired");
  t.eq("validate: only the one valid kit persisted", paired.length, 1);
  P.free();
}

// ── unknown message type ───────────────────────────────────────────────
{
  const { send } = await loadBackground();
  const res = await send({ type: "no-such-message" });
  t.truthy("dispatch: unknown message returns ok:false", res && res.ok === false);
}

t.done();
