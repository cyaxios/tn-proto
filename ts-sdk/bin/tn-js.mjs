#!/usr/bin/env node
// Minimal Node CLI for TN.
//
// Two subcommands, both JSON-lines on stdin/stdout so they compose:
//
//   tn-js seal < seal-input.json > envelope.ndjson
//   tn-js verify < envelope.ndjson
//
// `seal` expects one JSON object per line with this shape:
//   {
//     "seed_b64": "<base64 32 bytes>",
//     "event_type": "order.created",
//     "level": "info",
//     "sequence": 1,
//     "prev_hash": "sha256:...",
//     "timestamp": "2026-04-23T12:00:00Z",
//     "event_id": "uuid-v4",
//     "public_fields": { "amount": 100 }
//   }
// and writes one envelope ndjson line per input.
//
// `verify` reads envelope ndjson lines and writes one result line per
// input: {"ok": true, "row_hash": "...", "did": "...", "event_type": ...}
// or {"ok": false, "reason": "..."}.
//
// Encryption is not yet wired up; this CLI handles the public-only path
// so interop with Python can be proven byte-identically before btn
// and JWE are exposed through WASM. Both sides write to ndjson with
// compact separators and a trailing newline.

import { createInterface } from "node:readline";
import { Buffer } from "node:buffer";
import { stdin, stdout, argv, exit } from "node:process";

import {
  DeviceKey,
  NodeRuntime,
  asDid,
  asRowHash,
  asSignatureB64,
  buildEnvelopeLine,
  canonicalize,
  compileKitBundleToFile,
  rowHash,
  signatureB64,
  signatureFromB64,
  verify,
} from "../dist/index.js";

function die(msg) {
  process.stderr.write(`tn-js: ${msg}\n`);
  exit(2);
}

async function forEachLine(handler) {
  const rl = createInterface({ input: stdin, crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let input;
    try {
      input = JSON.parse(line);
    } catch (e) {
      die(`invalid JSON on stdin: ${e.message}`);
    }
    await handler(input);
  }
}

async function sealCmd() {
  await forEachLine((inp) => {
    const required = [
      "seed_b64",
      "event_type",
      "level",
      "sequence",
      "prev_hash",
      "timestamp",
      "event_id",
    ];
    for (const k of required) {
      if (!(k in inp)) die(`seal: missing field ${k}`);
    }
    const seed = new Uint8Array(Buffer.from(inp.seed_b64, "base64"));
    const dk = DeviceKey.fromSeed(seed);

    const rh = rowHash({
      did: dk.did,
      timestamp: inp.timestamp,
      eventId: inp.event_id,
      eventType: inp.event_type,
      level: inp.level,
      prevHash: asRowHash(inp.prev_hash),
      publicFields: inp.public_fields ?? {},
    });

    const sig = dk.sign(new Uint8Array(Buffer.from(rh, "utf8")));
    const sigB64 = signatureB64(sig);

    const line = buildEnvelopeLine({
      did: dk.did,
      timestamp: inp.timestamp,
      eventId: inp.event_id,
      eventType: inp.event_type,
      level: inp.level,
      sequence: inp.sequence,
      prevHash: asRowHash(inp.prev_hash),
      rowHash: rh,
      signatureB64: sigB64,
      publicFields: inp.public_fields ?? {},
    });
    stdout.write(line);
  });
}

async function verifyCmd() {
  await forEachLine((env) => {
    try {
      // Rebuild the row-hash input from public-only envelope fields.
      const {
        did,
        timestamp,
        event_id,
        event_type,
        level,
        sequence,
        prev_hash,
        row_hash,
        signature,
        ...rest
      } = env;

      for (const k of [
        "did",
        "timestamp",
        "event_id",
        "event_type",
        "level",
        "sequence",
        "prev_hash",
        "row_hash",
        "signature",
      ]) {
        if (env[k] === undefined) {
          return stdout.write(
            JSON.stringify({ ok: false, reason: `missing ${k}`, event_id }) + "\n",
          );
        }
      }

      // rest may carry public fields and group payloads. Split them.
      const publicFields = {};
      for (const [k, v] of Object.entries(rest)) {
        if (v && typeof v === "object" && !Array.isArray(v) && "ciphertext" in v) {
          // Group payload. Not handled in the public-only verify path.
          return stdout.write(
            JSON.stringify({
              ok: false,
              reason: `group payload ${k} present; public-only verify`,
              event_id,
            }) + "\n",
          );
        }
        publicFields[k] = v;
      }

      const recomputed = rowHash({
        did: asDid(did),
        timestamp,
        eventId: event_id,
        eventType: event_type,
        level,
        prevHash: asRowHash(prev_hash),
        publicFields,
      });

      if (recomputed !== row_hash) {
        return stdout.write(
          JSON.stringify({
            ok: false,
            reason: "row_hash mismatch",
            expected: recomputed,
            got: row_hash,
            event_id,
          }) + "\n",
        );
      }

      const sig = signatureFromB64(asSignatureB64(signature));
      const sigOk = verify(asDid(did), new Uint8Array(Buffer.from(row_hash, "utf8")), sig);
      if (!sigOk) {
        return stdout.write(
          JSON.stringify({ ok: false, reason: "bad signature", event_id }) + "\n",
        );
      }

      stdout.write(
        JSON.stringify({
          ok: true,
          did,
          event_type,
          event_id,
          row_hash,
          sequence,
        }) + "\n",
      );
    } catch (e) {
      stdout.write(JSON.stringify({ ok: false, reason: `exception: ${e.message}` }) + "\n");
    }
  });
}

async function canonicalCmd() {
  // Useful diagnostic: echo canonical bytes of stdin JSON.
  await forEachLine((inp) => {
    const bytes = canonicalize(inp);
    stdout.write(Buffer.from(bytes).toString("utf8") + "\n");
  });
}

function parseFieldArgs(rest) {
  // Accepts: --field k=v (string), --int k=v, --bool k=(true|false), --yaml <path>
  const out = { yaml: null, event: null, level: "info", fields: {} };
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === "--yaml") {
      out.yaml = rest[++i];
    } else if (a === "--event") {
      out.event = rest[++i];
    } else if (a === "--level") {
      out.level = rest[++i];
    } else if (a === "--field") {
      const [k, ...v] = rest[++i].split("=");
      out.fields[k] = v.join("=");
    } else if (a === "--int") {
      const [k, v] = rest[++i].split("=");
      out.fields[k] = Number.parseInt(v, 10);
    } else if (a === "--bool") {
      const [k, v] = rest[++i].split("=");
      out.fields[k] = v === "true";
    }
  }
  return out;
}

function infoCmd() {
  const args = parseFieldArgs(argv.slice(3));
  if (!args.yaml) die("info: --yaml <path> is required");
  if (!args.event) die("info: --event <type> is required");
  const rt = NodeRuntime.init(args.yaml);
  const receipt = rt.emit(args.level, args.event, args.fields);
  stdout.write(
    JSON.stringify({
      event_id: receipt.eventId,
      row_hash: receipt.rowHash,
      sequence: receipt.sequence,
    }) + "\n",
  );
}

function readCmd() {
  const rest = argv.slice(3);
  let yaml = null;
  let logPath = null;
  let compact = false;
  for (let i = 0; i < rest.length; i += 1) {
    if (rest[i] === "--yaml") yaml = rest[++i];
    else if (rest[i] === "--log") logPath = rest[++i];
    else if (rest[i] === "--compact") compact = true;
  }
  if (!yaml) die("read: --yaml <path> is required");
  const rt = NodeRuntime.init(yaml);
  let first = true;
  for (const entry of rt.read(logPath ?? undefined)) {
    const out = {
      event_type: entry.envelope.event_type,
      sequence: entry.envelope.sequence,
      timestamp: entry.envelope.timestamp,
      did: entry.envelope.did,
      row_hash: entry.envelope.row_hash,
      plaintext: entry.plaintext,
      valid: entry.valid,
    };
    if (compact) {
      stdout.write(JSON.stringify(out) + "\n");
    } else {
      if (!first) stdout.write("\n");
      stdout.write(JSON.stringify(out, null, 2) + "\n");
      first = false;
    }
  }
}

function compileCmd() {
  // Thin CLI over sdk's compileKitBundleToFile.
  const rest = argv.slice(3);
  const opts = { keystore: null, out: null, label: null, kits: [], full: false, yaml: null };
  for (let i = 0; i < rest.length; i += 1) {
    if (rest[i] === "--keystore") opts.keystore = rest[++i];
    else if (rest[i] === "--yaml") opts.yaml = rest[++i];
    else if (rest[i] === "--out") opts.out = rest[++i];
    else if (rest[i] === "--label") opts.label = rest[++i];
    else if (rest[i] === "--kit") opts.kits.push(rest[++i]);
    else if (rest[i] === "--full") opts.full = true;
  }
  if (!opts.out) die("compile: --out <file> is required");
  if (!opts.keystore && !opts.yaml) die("compile: provide --keystore <dir> or --yaml <path>");

  try {
    const result = compileKitBundleToFile({
      keystoreDir: opts.keystore ?? undefined,
      yamlPath: opts.yaml ?? undefined,
      outPath: opts.out,
      groups: opts.kits.length ? opts.kits : undefined,
      label: opts.label ?? undefined,
      full: opts.full,
    });
    stdout.write(
      JSON.stringify({
        ok: true,
        out: result.outPath,
        kits: result.kits,
        kind: result.manifest.kind,
        label: result.manifest.label,
      }) + "\n",
    );
  } catch (e) {
    die(e.message);
  }
}

function adminCmd() {
  const sub = argv[3];
  const rest = argv.slice(4);
  const opts = { yaml: null, group: "default", out: null, did: null, leaf: null };
  for (let i = 0; i < rest.length; i += 1) {
    if (rest[i] === "--yaml") opts.yaml = rest[++i];
    else if (rest[i] === "--group") opts.group = rest[++i];
    else if (rest[i] === "--out") opts.out = rest[++i];
    else if (rest[i] === "--recipient-did") opts.did = rest[++i];
    else if (rest[i] === "--leaf") opts.leaf = Number.parseInt(rest[++i], 10);
  }
  if (!opts.yaml) die("admin: --yaml <path> is required");
  const rt = NodeRuntime.init(opts.yaml);

  switch (sub) {
    case "add-recipient": {
      if (!opts.out) die("admin add-recipient: --out <kit-path> is required");
      const leaf = rt.addRecipient(opts.group, opts.out, opts.did ?? undefined);
      stdout.write(
        JSON.stringify({
          ok: true,
          group: opts.group,
          leaf_index: leaf,
          kit_path: opts.out,
          recipient_did: opts.did,
        }) + "\n",
      );
      break;
    }
    case "revoke-recipient": {
      if (opts.leaf == null || Number.isNaN(opts.leaf)) {
        die("admin revoke-recipient: --leaf <index> is required");
      }
      rt.revokeRecipient(opts.group, opts.leaf, opts.did ?? undefined);
      stdout.write(JSON.stringify({ ok: true, group: opts.group, leaf_index: opts.leaf }) + "\n");
      break;
    }
    case "revoked-count": {
      const count = rt.revokedCount(opts.group);
      stdout.write(JSON.stringify({ ok: true, group: opts.group, count }) + "\n");
      break;
    }
    default:
      die(`admin: unknown subcommand ${sub}. try add-recipient | revoke-recipient | revoked-count`);
  }
}

const cmd = argv[2];
switch (cmd) {
  case "seal":
    await sealCmd();
    break;
  case "verify":
    await verifyCmd();
    break;
  case "canonical":
    await canonicalCmd();
    break;
  case "info":
    infoCmd();
    break;
  case "read":
    readCmd();
    break;
  case "admin":
    adminCmd();
    break;
  case "compile":
    compileCmd();
    break;
  case undefined:
  case "--help":
  case "-h":
    process.stderr.write(
      "tn-js <seal|verify|canonical|info|read>\n" +
        "  seal       stdin JSON -> ndjson envelope line on stdout\n" +
        "  verify     ndjson envelope line -> {ok, ...} on stdout\n" +
        "  canonical  stdin JSON -> canonical UTF-8 line on stdout\n" +
        "  info       --yaml <path> --event <type> [--level info] --field k=v ...\n" +
        "             Append one attested entry to the log defined in yaml.\n" +
        "  read       --yaml <path> [--log <path>] [--compact]\n" +
        "             Iterate decoded entries as pretty JSON on stdout.\n" +
        "             Includes plaintext (per-group) and valid {signature,rowHash,chain}.\n" +
        "             --compact: one JSON line per entry instead of pretty-print.\n" +
        "  admin add-recipient     --yaml <path> [--group default] --out <kit-path>\n" +
        "                          [--recipient-did did:key:...]\n" +
        "  admin revoke-recipient  --yaml <path> [--group default] --leaf <index>\n" +
        "                          [--recipient-did did:key:...]\n" +
        "  admin revoked-count     --yaml <path> [--group default]\n" +
        "  compile    --keystore <dir>  --out <file.tnpkg>  [--kit <group>]... [--label <text>] [--full]\n" +
        "             Package *.btn.mykit files into a .tnpkg (zip w/ manifest.json + kits) that the\n" +
        "             Chrome extension, Python SDK, and tn-js can all import.\n" +
        "             --kit filters to named groups; --full also writes publisher state + signing seed.\n" +
        "             --yaml <path> may be used in place of --keystore to infer the keystore dir.\n",
    );
    exit(cmd ? 0 : 1);
    break;
  default:
    die(`unknown command: ${cmd}`);
}
