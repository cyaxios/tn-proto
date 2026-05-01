// Stand-alone verification: drive the content-script regex + the
// service-worker decrypt path against a real btn ciphertext, without
// Chrome. If this passes, the detection + decrypt path in the
// extension is wired correctly. Loads the same tn-wasm Node-target
// bundle the SDK uses so the crypto is identical.

import { Buffer } from "node:buffer";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const wasmPkg = resolve(here, "../../../crypto/tn-wasm/pkg");
const {
  BtnPublisher,
  btnDecrypt,
  btnCiphertextPublisherId,
  btnKitPublisherId,
  canonicalBytes,
  computeRowHash,
  buildEnvelope,
  deriveDidKey,
  deriveGroupIndexKey,
  deviceKeyFromSeed,
  indexToken,
  signMessage,
  signatureB64,
  zeroHash,
} = await import(pathToFileURL(wasmPkg + "/tn_wasm.js").href);

function b64(b) { return Buffer.from(b).toString("base64"); }
function hex(b) { return Buffer.from(b).toString("hex"); }

// Mirror of the new content.js detection: every base64 chunk of 40+
// chars in a text node is a candidate. The SW is the sole decider.
const B64_CHUNK = /[A-Za-z0-9+/]{40,}={0,2}/g;

function findCandidates(text) {
  const out = [];
  B64_CHUNK.lastIndex = 0;
  let m;
  while ((m = B64_CHUNK.exec(text)) !== null) {
    out.push({ b64: m[0], match: m[0], index: m.index });
  }
  return out;
}

// Mirror of background.js:classifyOne across N unlocked keystores in a
// resolution order. Returns one of:
//   { class: "decrypted", plaintext_json, publisher_id_hex, keystore_label }
//   { class: "sealed", publisher_id_hex }
//   { class: "not-tn" }
function serviceWorkerClassify(keystores, order, candidateB64) {
  let ctBytes;
  try { ctBytes = Buffer.from(candidateB64, "base64"); } catch { return { class: "not-tn" }; }
  let pubId;
  try { pubId = hex(btnCiphertextPublisherId(ctBytes)); }
  catch { return { class: "not-tn" }; }
  for (const id of order) {
    const ks = keystores.get(id);
    if (!ks) continue;
    const kits = ks.kits.get(pubId);
    if (!kits) continue;
    for (const kit of kits) {
      try {
        const pt = btnDecrypt(kit, ctBytes);
        let json = null;
        try { json = JSON.parse(Buffer.from(pt).toString("utf8")); } catch {}
        return { class: "decrypted", plaintext_json: json, publisher_id_hex: pubId, keystore_label: ks.label };
      } catch {}
    }
  }
  return { class: "sealed", publisher_id_hex: pubId };
}

// ---------------------------------------------------------------------
// Build two ceremonies (publisher A and publisher B), produce one log
// line each, then load publisher A's self-kit and confirm:
//   - A's ciphertext decrypts to the expected plaintext
//   - B's ciphertext reports "no kit for publisher" and isn't touched
//   - Each envelope passes the ROW_HASH regex (so the content script
//     only lights up on real envelopes).
// ---------------------------------------------------------------------

function makeCeremony(seedByte) {
  const devSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) devSeed[i] = (seedByte + i) & 0xff;
  const btnSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) btnSeed[i] = (seedByte + i * 3 + 7) & 0xff;
  const idx = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) idx[i] = (seedByte + i * 5) & 0xff;
  const dk = deviceKeyFromSeed(devSeed);
  const pub = new BtnPublisher(btnSeed);
  const mykit = pub.mint();
  return {
    devSeed, dk, pub, mykit, idx,
    ceremony: `fixture_${seedByte.toString(16)}`,
  };
}

function buildLine(c, pubF, privF) {
  const ct = c.pub.encrypt(canonicalBytes(privF));
  return { ciphertext: b64(ct), plaintext: privF };
}

let passed = 0, failed = 0;
function ok(m) { console.log(`[ok]   ${m}`); passed += 1; }
function fail(m, w) { console.log(`[fail] ${m}: ${w}`); failed += 1; }

const A = makeCeremony(13);
const B = makeCeremony(97);

const lineA = buildLine(A, { region: "us-east-1" }, { customer_name: "Alice", amount: 99.50 });
const lineB = buildLine(B, { region: "eu-west-1" }, { customer_name: "Bob", amount: 12 });

// Real log viewers render JSON log lines as per-field rows. Simulate
// the cell the vendor UI would produce for the ciphertext field only.
// The new detector does NOT require row_hash to be nearby: each cell is
// its own text node.
const dashboardText = [
  lineA.ciphertext,
  lineB.ciphertext,
  "ordinary log line with no envelope at all, plus some short uuid-like string like 01ABCDEFGHJKLMNPQRSTUVWXYZ01",
  "a random long base64 that is NOT a btn ciphertext: " + Buffer.from("the quick brown fox jumps over the lazy dog repeatedly to make it long enough to look suspicious")
    .toString("base64"),
].join("\n\n");

const candidates = findCandidates(dashboardText);
if (candidates.length >= 3) ok(`detector found ${candidates.length} base64 candidates`);
else fail("candidate count", `only ${candidates.length}`);

// Service worker with two keystores: only A is unlocked.
const ksA = { label: "Alice's orders", kits: new Map() };
ksA.kits.set(hex(btnKitPublisherId(A.mykit)), [A.mykit]);
const keystores = new Map([["ks_A", ksA]]);
const order = ["ks_A"];

const results = candidates.map((c) => serviceWorkerClassify(keystores, order, c.b64));

const decrypted = results.filter((r) => r.class === "decrypted");
const sealed = results.filter((r) => r.class === "sealed");
const notTn = results.filter((r) => r.class === "not-tn");

if (decrypted.length === 1 && decrypted[0].plaintext_json?.customer_name === "Alice") {
  ok("exactly one decrypts (A's ciphertext -> Alice)");
} else {
  fail("decrypted count", JSON.stringify(decrypted));
}

if (sealed.length === 1) ok("B's ciphertext classified as sealed (btn, no kit)");
else fail("sealed count", `expected 1, got ${sealed.length}`);

if (notTn.length >= 1) ok(`${notTn.length} not-tn candidate(s) properly rejected (noise, uuids)`);
else fail("not-tn count", "expected >=1");

if (!results.some((r) => r.class === "decrypted" && r.plaintext_json?.customer_name === "Bob")) {
  ok("B's plaintext does NOT leak without B's kit");
} else {
  fail("B leak", "Bob decrypted unexpectedly");
}

// Multi-keystore + ordering: give B's kit under a SECOND keystore at a
// lower priority. Since there's no kit collision, both keystores just
// merge their coverage. B should now decrypt.
const ksB = { label: "Bob's extras", kits: new Map() };
ksB.kits.set(hex(btnKitPublisherId(B.mykit)), [B.mykit]);
keystores.set("ks_B", ksB);
order.push("ks_B");

const results2 = candidates.map((c) => serviceWorkerClassify(keystores, order, c.b64));
const okA = results2.find((r) => r.class === "decrypted" && r.plaintext_json?.customer_name === "Alice");
const okB = results2.find((r) => r.class === "decrypted" && r.plaintext_json?.customer_name === "Bob");
if (okA && okB) {
  ok("with both keystores loaded, A and B both decrypt");
} else {
  fail("two-keystore decrypt", `okA=${!!okA}, okB=${!!okB}`);
}

if (okA && okA.keystore_label === "Alice's orders" && okB && okB.keystore_label === "Bob's extras") {
  ok("keystore_label is attributed correctly per result");
} else {
  fail("label attribution", `${okA?.keystore_label} / ${okB?.keystore_label}`);
}

// ---------------------------------------------------------------------
// Popup paste-and-decrypt path (D-1, D-22).
//
// Mirrors background.js::popupDecrypt: parses the user's pasted input
// (b64 or hex), sweeps every kit in every loaded keystore, returns the
// first successful plaintext along with which keystore matched.
//
// Exercised through a mocked chrome.runtime so the request shape and
// response contract are pinned down exactly as the popup will see them.
// ---------------------------------------------------------------------

function parsePastedCiphertext(text) {
  const raw = (text || "").trim();
  if (!raw) return null;
  // Hex first — chars are a subset of base64 so b64 regex would match too.
  const hexs = raw.replace(/[\s:]+/g, "");
  if (/^[0-9a-fA-F]+$/.test(hexs) && hexs.length % 2 === 0 && hexs.length > 0) {
    const out = new Uint8Array(hexs.length / 2);
    for (let i = 0; i < out.length; i += 1) {
      out[i] = parseInt(hexs.slice(i * 2, i * 2 + 2), 16);
    }
    return { bytes: out, format: "hex" };
  }
  try {
    const cleaned = raw.replace(/\s+/g, "");
    if (/^[A-Za-z0-9_+/=-]+$/.test(cleaned) && cleaned.length >= 4) {
      const norm = cleaned.replace(/-/g, "+").replace(/_/g, "/");
      const padded = norm + "=".repeat((4 - norm.length % 4) % 4);
      const out = Buffer.from(padded, "base64");
      if (out.length > 0) return { bytes: new Uint8Array(out), format: "b64" };
    }
  } catch { /* fall through */ }
  return null;
}

function tryUtf8(bytes) {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (/[\x00-\x08\x0e-\x1f]/.test(text)) return null;
    return text;
  } catch { return null; }
}

function popupDecryptHandler(unlocked, msg) {
  const parsed = parsePastedCiphertext(msg.ciphertext_b64);
  if (!parsed) return { ok: false, reason: "input is neither base64 nor hex" };
  if (unlocked.size === 0) return { ok: false, reason: "no kits loaded — import or pair first" };
  let tried = 0;
  for (const [id, ks] of unlocked.entries()) {
    for (const [pubId, kits] of ks.kits.entries()) {
      for (const kit of kits) {
        tried += 1;
        try {
          const pt = btnDecrypt(kit, parsed.bytes);
          return {
            ok: true,
            plaintext_b64: b64(pt),
            plaintext_utf8: tryUtf8(pt),
            keystore_id: id,
            keystore_label: ks.label,
            group: ks.group || null,
            publisher_id_hex: pubId,
            kits_tried: tried,
          };
        } catch { /* try next */ }
      }
    }
  }
  return { ok: false, reason: "no kit matched", kits_tried: tried };
}

// Mock chrome.runtime.sendMessage. The popup uses this exact API; we
// ensure the message shape and response shape match what the SW
// dispatcher in background.js will produce.
function makeMockChromeRuntime(unlocked) {
  return {
    runtime: {
      sendMessage: async (msg) => {
        if (msg.type !== "tn:popup-decrypt") {
          return { ok: false, reason: "unknown message " + msg.type };
        }
        return popupDecryptHandler(unlocked, msg);
      },
    },
  };
}

// keystores already populated above with A and B unlocked.
const popupKeystores = new Map();
const ksAforPopup = { label: "Alice's orders", kits: new Map(), group: "alice-group" };
ksAforPopup.kits.set(hex(btnKitPublisherId(A.mykit)), [A.mykit]);
popupKeystores.set("ks_A", ksAforPopup);

const chromeMock = makeMockChromeRuntime(popupKeystores);

// Test 1: paste A's ciphertext as base64, expect a hit with Alice's label.
{
  const resp = await chromeMock.runtime.sendMessage({
    type: "tn:popup-decrypt",
    ciphertext_b64: lineA.ciphertext,
  });
  if (resp.ok && resp.keystore_label === "Alice's orders") {
    ok("popup-decrypt: b64 input hits the right keystore");
  } else {
    fail("popup-decrypt b64", JSON.stringify(resp));
  }
  // The plaintext_b64 round-trips back to Alice's plaintext JSON.
  const pt = Buffer.from(resp.plaintext_b64, "base64").toString("utf8");
  const parsed = JSON.parse(pt);
  if (parsed.customer_name === "Alice") {
    ok("popup-decrypt: plaintext_b64 carries Alice's plaintext");
  } else {
    fail("popup-decrypt plaintext", JSON.stringify(parsed));
  }
  if (resp.plaintext_utf8 && resp.plaintext_utf8.includes("Alice")) {
    ok("popup-decrypt: plaintext_utf8 populated for printable bytes");
  } else {
    fail("popup-decrypt utf8", `got ${resp.plaintext_utf8}`);
  }
  if (resp.group === "alice-group") {
    ok("popup-decrypt: group field surfaces from the matched keystore");
  } else {
    fail("popup-decrypt group", `got ${resp.group}`);
  }
}

// Test 2: paste A's ciphertext as HEX (whitespace tolerated), expect same hit.
{
  const ctBytes = Buffer.from(lineA.ciphertext, "base64");
  const hexStr = Array.from(ctBytes).map((b) => b.toString(16).padStart(2, "0")).join(" ");
  const resp = await chromeMock.runtime.sendMessage({
    type: "tn:popup-decrypt",
    ciphertext_b64: hexStr,
  });
  if (resp.ok && resp.keystore_label === "Alice's orders") {
    ok("popup-decrypt: hex input parses and decrypts");
  } else {
    fail("popup-decrypt hex", JSON.stringify(resp));
  }
}

// Test 3: B's ciphertext with only A loaded -> no kit matched.
{
  const resp = await chromeMock.runtime.sendMessage({
    type: "tn:popup-decrypt",
    ciphertext_b64: lineB.ciphertext,
  });
  if (!resp.ok && resp.reason === "no kit matched") {
    ok("popup-decrypt: B's ciphertext rejected with 'no kit matched'");
  } else {
    fail("popup-decrypt no-match", JSON.stringify(resp));
  }
}

// Test 4: bogus input rejected without trying any kits.
{
  const resp = await chromeMock.runtime.sendMessage({
    type: "tn:popup-decrypt",
    ciphertext_b64: "!!! not b64 not hex !!!",
  });
  if (!resp.ok && resp.reason === "input is neither base64 nor hex") {
    ok("popup-decrypt: bad input rejected before any kit tried");
  } else {
    fail("popup-decrypt bad-input", JSON.stringify(resp));
  }
}

// Test 5: empty unlocked map -> "no kits loaded" hint.
{
  const emptyMock = makeMockChromeRuntime(new Map());
  const resp = await emptyMock.runtime.sendMessage({
    type: "tn:popup-decrypt",
    ciphertext_b64: lineA.ciphertext,
  });
  if (!resp.ok && /no kits loaded/.test(resp.reason)) {
    ok("popup-decrypt: empty keystore returns 'no kits loaded' hint");
  } else {
    fail("popup-decrypt empty", JSON.stringify(resp));
  }
}

// Test 6: with B's keystore added, B's ciphertext now decrypts to Bob.
{
  const ksBforPopup = { label: "Bob's extras", kits: new Map(), group: "bob-group" };
  ksBforPopup.kits.set(hex(btnKitPublisherId(B.mykit)), [B.mykit]);
  popupKeystores.set("ks_B", ksBforPopup);
  const resp = await chromeMock.runtime.sendMessage({
    type: "tn:popup-decrypt",
    ciphertext_b64: lineB.ciphertext,
  });
  const pt = resp.ok ? Buffer.from(resp.plaintext_b64, "base64").toString("utf8") : "";
  const parsed = pt ? JSON.parse(pt) : {};
  if (resp.ok && parsed.customer_name === "Bob" && resp.keystore_label === "Bob's extras") {
    ok("popup-decrypt: second keystore decrypts B and reports correct label");
  } else {
    fail("popup-decrypt B-decrypt", JSON.stringify(resp));
  }
}

A.pub.free(); B.pub.free();

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
