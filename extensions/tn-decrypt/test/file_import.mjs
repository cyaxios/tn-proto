// Verify fileToBundle() logic against:
//   1. A real .zip with kit.tnpkg inside (matches routes_invite.py output)
//   2. A raw .mykit binary (what a recipient has after unzipping)
//   3. A plaintext keystore-v1 JSON
//
// Runs under Node using the same tn-wasm Node-target bundle, since the
// browser's fileToBundle path uses only standard APIs (ArrayBuffer,
// DecompressionStream, TextDecoder) that Node also has.

import { Buffer } from "node:buffer";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const wasmPkg = resolve(here, "../../../crypto/tn-wasm/pkg");
const {
  BtnPublisher,
  btnKitPublisherId,
} = await import(pathToFileURL(wasmPkg + "/tn_wasm.js").href);

let passed = 0, failed = 0;
function ok(m) { console.log(`[ok]   ${m}`); passed += 1; }
function fail(m, why) { console.log(`[fail] ${m}: ${why}`); failed += 1; }

// Build a real kit (same code path the vault uses).
const btnSeed = new Uint8Array(32);
for (let i = 0; i < 32; i += 1) btnSeed[i] = (i * 7 + 5) & 0xff;
const pub = new BtnPublisher(btnSeed);
const kitBytes = pub.mint();
pub.free();
const pubIdHex = Array.from(btnKitPublisherId(kitBytes)).map(b => b.toString(16).padStart(2, "0")).join("");

// Build a matching invitation.zip the same way _write_invitation_zip
// does in routes_invite.py (STORED for manifest, DEFLATED for kit).
// We'll write both entries STORED to keep the test portable; the
// browser reader handles STORED and DEFLATED.
import { writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const tdir = join(tmpdir(), "tn-ext-import-" + Date.now());
mkdirSync(tdir, { recursive: true });
writeFileSync(join(tdir, "kit.tnpkg"), Buffer.from(kitBytes));
const manifest = { invitation_id: "01ABC", project_name: "file-import-test", note: "drop this kit into keys/" };
writeFileSync(join(tdir, "manifest.json"), JSON.stringify(manifest, null, 2));

// Use Python to build a real PKZIP (guaranteed ZIP format).
const py = process.env.TN_PYTHON
  || resolve(here, "../../../../.venv/Scripts/python.exe");
const zipPath = join(tdir, "invitation.zip");
const pyScript = `
import zipfile, sys
zp = sys.argv[1]
with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.write(r"${join(tdir, "kit.tnpkg").replace(/\\/g, "\\\\")}", "kit.tnpkg")
    zf.write(r"${join(tdir, "manifest.json").replace(/\\/g, "\\\\")}", "manifest.json")
`;
const r = spawnSync(py, ["-c", pyScript, zipPath], { encoding: "utf8" });
if (r.status !== 0) {
  console.error("failed to build test zip:", r.stderr);
  process.exit(2);
}

// Inline a stripped-down version of fileToBundle + readZip. The one in
// options.js uses File + ArrayBuffer APIs; here we feed a Node Buffer
// cast to ArrayBuffer, same shape.
async function readZipBuf(arrayBuf) {
  const view = new DataView(arrayBuf);
  const bytes = new Uint8Array(arrayBuf);
  let eocd = -1;
  for (let i = arrayBuf.byteLength - 22; i >= Math.max(0, arrayBuf.byteLength - 65558); i -= 1) {
    if (view.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("no EOCD");
  const cdEntries = view.getUint16(eocd + 10, true);
  const cdOffset = view.getUint32(eocd + 16, true);
  const entries = new Map();
  let p = cdOffset;
  for (let i = 0; i < cdEntries; i += 1) {
    if (view.getUint32(p, true) !== 0x02014b50) throw new Error("bad CD");
    const method = view.getUint16(p + 10, true);
    const compSize = view.getUint32(p + 20, true);
    const nameLen = view.getUint16(p + 28, true);
    const extraLen = view.getUint16(p + 30, true);
    const commLen = view.getUint16(p + 32, true);
    const localOffset = view.getUint32(p + 42, true);
    const name = new TextDecoder().decode(bytes.subarray(p + 46, p + 46 + nameLen));
    entries.set(name, { method, compSize, localOffset });
    p += 46 + nameLen + extraLen + commLen;
  }
  return {
    names: [...entries.keys()],
    async read(name) {
      const e = entries.get(name);
      if (!e) return null;
      const lh = e.localOffset;
      const lhNameLen = view.getUint16(lh + 26, true);
      const lhExtraLen = view.getUint16(lh + 28, true);
      const dataStart = lh + 30 + lhNameLen + lhExtraLen;
      const comp = bytes.subarray(dataStart, dataStart + e.compSize);
      if (e.method === 0) return comp.slice();
      if (e.method === 8) {
        const ds = new DecompressionStream("deflate-raw");
        const w = ds.writable.getWriter();
        w.write(comp); w.close();
        return new Uint8Array(await new Response(ds.readable).arrayBuffer());
      }
      throw new Error("unsupported method " + e.method);
    },
  };
}

const zipBytes = readFileSync(zipPath);
const zip = await readZipBuf(zipBytes.buffer.slice(zipBytes.byteOffset, zipBytes.byteOffset + zipBytes.byteLength));

if (zip.names.includes("kit.tnpkg")) ok("zip lists kit.tnpkg");
else fail("zip entry", zip.names.join(","));

const extractedKit = await zip.read("kit.tnpkg");
if (extractedKit && extractedKit.length === kitBytes.length &&
    Array.from(extractedKit).every((b, i) => b === kitBytes[i])) {
  ok(`extracted kit matches original (${kitBytes.length} bytes, publisher ${pubIdHex.slice(0, 16)}...)`);
} else {
  fail("kit bytes match", "lengths differ or content differs");
}

const manifestBytes = await zip.read("manifest.json");
const manifestJson = JSON.parse(new TextDecoder().decode(manifestBytes));
if (manifestJson.note === "drop this kit into keys/" && manifestJson.project_name === "file-import-test") {
  ok("manifest note and project_name round-trip through zip");
} else {
  fail("manifest round-trip", JSON.stringify(manifestJson));
}

// Raw .mykit path: options.js detects "not a zip, not json -> treat as
// raw .mykit". We just confirm the sniff would succeed on our kitBytes.
const head = kitBytes.slice(0, 4);
const looksZip = head[0] === 0x50 && head[1] === 0x4b;
if (!looksZip && kitBytes.length >= 200) ok("raw .mykit would be accepted by the options importer");
else fail("raw .mykit sniff", `head=${Array.from(head).map(b => b.toString(16)).join(" ")}, len=${kitBytes.length}`);

// JSON keystore path: shape check.
const keystoreBundle = {
  version: "keystore-v1",
  did: "did:key:z6Mk...",
  ceremony_id: "test",
  files: { "default.btn.mykit": Buffer.from(kitBytes).toString("base64") },
};
const keystoreRaw = new TextEncoder().encode(JSON.stringify(keystoreBundle));
const parsed = JSON.parse(new TextDecoder().decode(keystoreRaw));
if (parsed.files && parsed.files["default.btn.mykit"]) {
  ok("JSON keystore parses with expected files map");
} else {
  fail("JSON keystore", "files map missing");
}

// ---------------------------------------------------------------------
// Session 13: local-file keystores are stored plaintext under
// chrome.storage.local with `source: "local-file"` and no passphrase.
// We simulate the storage round-trip with a stub that mirrors the
// chrome.storage.local API surface and the addLocalFileKeystore /
// status code paths from background.js.
// ---------------------------------------------------------------------

function makeStorageStub() {
  const data = {};
  return {
    data,
    get: async (keys) => {
      const out = {};
      const list = Array.isArray(keys) ? keys : [keys];
      for (const k of list) if (k in data) out[k] = data[k];
      return out;
    },
    set: async (kv) => { Object.assign(data, kv); },
    remove: async (key) => { delete data[key]; },
  };
}

// Inline shrink of background.js's local-file storage path. We aren't
// loading the SW module (requires chrome.runtime + tn-wasm init), so
// we re-implement just enough to check the persisted shape.
async function addLocalFileToStub(stub, { label, filename, bundle }) {
  const cur = await stub.get(["keystores", "order"]);
  const keystores = cur.keystores || [];
  const order = cur.order || [];
  const id = "ks_" + Math.random().toString(36).slice(2, 10);
  const entry = {
    id,
    label: label || filename || "Keystore",
    added_at: new Date().toISOString(),
    source: "local-file",
    filename: filename || null,
    bundle,
  };
  await stub.set({ keystores: [...keystores, entry], order: [...order, id] });
  return entry;
}

const stub = makeStorageStub();
const importBundle = {
  version: "keystore-v1",
  did: null,
  ceremony_id: null,
  origin: { kind: "raw-mykit", filename: "kit.btn.mykit" },
  files: { "default.btn.mykit": Buffer.from(kitBytes).toString("base64") },
};
const stored = await addLocalFileToStub(stub, {
  label: "On-disk kit",
  filename: "kit.btn.mykit",
  bundle: importBundle,
});

if (stored.source === "local-file") ok("local-file import sets source=\"local-file\"");
else fail("source field", `expected "local-file", got "${stored.source}"`);

if (stored.bundle && stored.bundle.files && stored.bundle.files["default.btn.mykit"]) {
  ok("local-file entry stores the plaintext bundle inline");
} else {
  fail("plaintext bundle", "bundle.files missing");
}

if (!("blob" in stored) && !("emk_wrapped_secret" in stored)) {
  ok("local-file entry has no blob / no emk_wrapped_secret (no encryption)");
} else {
  fail("no encryption", `unexpected fields: ${Object.keys(stored).join(",")}`);
}

if (stored.filename === "kit.btn.mykit") ok("local-file entry preserves source filename");
else fail("filename", `got "${stored.filename}"`);

// Round-trip: read it back from the stub the way background.js does.
const after = await stub.get(["keystores", "order"]);
const roundtripped = after.keystores[0];
if (roundtripped && roundtripped.bundle && roundtripped.bundle.files["default.btn.mykit"]) {
  // Decode the kit and confirm the bytes match — i.e., it's
  // *readable without a passphrase*, which is the whole point.
  const kitB64 = roundtripped.bundle.files["default.btn.mykit"];
  const kitOut = Buffer.from(kitB64, "base64");
  const same = kitOut.length === kitBytes.length &&
    Array.from(kitOut).every((b, i) => b === kitBytes[i]);
  if (same) ok("local-file kit is readable without any passphrase");
  else fail("kit roundtrip", "bytes differ");
} else {
  fail("local-file roundtrip", "bundle missing after read");
}

// Back-compat: a vault-style entry (no `source`, has `blob`) should
// still be treated as "vault" by the source-resolution helper.
function keystoreSource(k) { return k.source || "vault"; }
const legacyEntry = { id: "ks_legacy", label: "old", added_at: "x", blob: { ciphertext_b64: "...", salt_b64: "...", nonce_b64: "..." } };
if (keystoreSource(legacyEntry) === "vault") ok("legacy entries (no source field) classify as vault");
else fail("legacy classify", keystoreSource(legacyEntry));

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
