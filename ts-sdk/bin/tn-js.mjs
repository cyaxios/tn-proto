#!/usr/bin/env node
// Minimal Node CLI for TN.
//
// Subcommands:
//
//   tn-js seal < seal-input.json > envelope.ndjson
//   tn-js verify < envelope.ndjson
//   tn-js watch --yaml ./tn.yaml [--since start|now|<seq>|<iso-ts>] [--verify] [--poll <ms>] [--once]
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
import { existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve as pathResolve } from "node:path";

import {
  DeviceKey,
  NodeRuntime,
  asDid,
  asRowHash,
  asSignatureB64,
  buildEnvelopeLine,
  canonicalize,
  close as tnClose,
  compileKitBundleToFile,
  config as tnConfig,
  init as tnInit,
  rowHash,
  signatureB64,
  signatureFromB64,
  verify,
} from "../dist/index.js";

import { ensureCeremonyOnDisk } from "../dist/multi.js";
import { resolveVaultUrl } from "../dist/vault/url.js";
import { Identity, defaultIdentityPath } from "../dist/identity.js";
import { AccountConnectError, AccountNamespace } from "../dist/account/index.js";
import { VaultClient, VaultError, vaultIdentityFromDeviceKey } from "../dist/vault/client.js";
import { WalletNamespace, readLinkState, readSyncQueue } from "../dist/wallet/index.js";
import { restoreViaLoopback } from "../dist/wallet/restore.js";
import { loadKeystore } from "../dist/runtime/keystore.js";

import { bundleCmd } from "../dist/cli/bundle.js";
import { addRecipientCmd } from "../dist/cli/add_recipient.js";
import { absorbCmd } from "../dist/cli/absorb.js";
import { groupAddCmd } from "../dist/cli/group_add.js";
import { showProfilesCmd } from "../dist/cli/show_profiles.js";
import { walletPullPrefsCmd } from "../dist/cli/wallet_pull_prefs.js";
import { walletExportMnemonicCmd } from "../dist/cli/wallet_export_mnemonic.js";
import { firehoseCmd } from "../dist/cli/firehose.js";
import { walletSyncCmd } from "../dist/cli/wallet_sync.js";
import { inboxAcceptCmd } from "../dist/cli/inbox_accept.js";
import { inboxListLocalCmd } from "../dist/cli/inbox_list_local.js";

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
      device_identity: dk.did,
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
      device_identity: dk.did,
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
        device_identity,
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
        "device_identity",
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
        device_identity: asDid(device_identity),
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
      const sigOk = verify(asDid(device_identity), new Uint8Array(Buffer.from(row_hash, "utf8")), sig);
      if (!sigOk) {
        return stdout.write(
          JSON.stringify({ ok: false, reason: "bad signature", event_id }) + "\n",
        );
      }

      stdout.write(
        JSON.stringify({
          ok: true,
          did: device_identity,
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
      device_identity: entry.envelope.device_identity,
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

async function watchCmd() {
  // Args after the subcommand: --yaml <path>, --since <start|now|<seq>|<iso-ts>>,
  // --verify, --poll <ms>, --once.
  const args = argv.slice(3);
  let yamlPath = null;
  let since = "now";
  let verify = false;
  let pollMs = 300;
  let once = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--yaml") yamlPath = args[++i];
    else if (a === "--since") since = args[++i];
    else if (a === "--verify") verify = true;
    else if (a === "--poll") pollMs = Number(args[++i]);
    else if (a === "--once") once = true;
    else die(`watch: unknown arg ${a}`);
  }

  // Coerce --since: "start" | "now" stay as strings; pure-digit value
  // becomes a sequence number; otherwise treat as ISO-8601 timestamp.
  let sinceVal = since;
  if (since !== "start" && since !== "now" && /^\d+$/.test(since)) {
    sinceVal = Number(since);
  }

  const { Tn } = await import("../dist/index.js");
  const tn = yamlPath ? await Tn.init(yamlPath) : await Tn.init();

  // Set up SIGINT to stop cleanly. We can't easily abort an in-flight
  // for-await iteration without an AbortSignal, so flip a flag and
  // break on the next yield.
  let stopping = false;
  const onSigint = () => {
    stopping = true;
    process.stderr.write("\ntn-js watch: stopping (SIGINT)\n");
  };
  process.on("SIGINT", onSigint);

  try {
    if (once) {
      // --once: drain everything currently in the log starting from
      // `since`, then exit. Use tn.read for the snapshot read; this
      // matches Python's `python -m tn.watch --once` shape.
      const opts = {};
      if (verify) opts.verify = true;
      const startAt =
        sinceVal === "start" ? null :
        sinceVal === "now" ? "skip" :
        sinceVal;
      // Walk the snapshot. For "now", we'd skip everything — that's
      // a no-op, exit 0. For "start", iterate everything. For a
      // seq/timestamp, filter.
      if (startAt === "skip") {
        // no-op; exit 0
      } else if (startAt === null) {
        opts.allRuns = true;
        for (const entry of tn.read(opts)) {
          stdout.write(JSON.stringify(entry) + "\n");
        }
      } else {
        opts.allRuns = true;
        for (const entry of tn.read(opts)) {
          // entry.timestamp is a Date (Entry); coerce to ISO for the
          // string-comparison branch. entry.sequence is a number.
          const tsIso =
            entry.timestamp instanceof Date
              ? entry.timestamp.toISOString()
              : typeof entry.timestamp === "string"
                ? entry.timestamp
                : "";
          const matches =
            typeof startAt === "number"
              ? typeof entry.sequence === "number" && entry.sequence >= startAt
              : tsIso !== "" && tsIso >= startAt;
          if (matches) {
            stdout.write(JSON.stringify(entry) + "\n");
          }
        }
      }
    } else {
      // Tail forever (until SIGINT).
      const watchOpts = { since: sinceVal, verify, pollIntervalMs: pollMs };
      for await (const entry of tn.watch(watchOpts)) {
        if (stopping) break;
        stdout.write(JSON.stringify(entry) + "\n");
      }
    }
  } finally {
    process.removeListener("SIGINT", onSigint);
    await tn.close();
  }
}

async function streamsCmd() {
  // List ceremonies under .tn/ for the project. Mirrors Python's
  // ``tn streams`` subcommand (python/tn/cli.py:cmd_streams).
  const rest = argv.slice(3);
  const opts = { projectDir: null, format: "human" };
  for (let i = 0; i < rest.length; i += 1) {
    if (rest[i] === "--project-dir") opts.projectDir = rest[++i];
    else if (rest[i] === "--format") opts.format = rest[++i];
  }
  const { existsSync, readdirSync, readFileSync } = await import("node:fs");
  const { join, resolve: pathResolve } = await import("node:path");
  const projectDir = opts.projectDir ? pathResolve(opts.projectDir) : process.cwd();
  const root = join(projectDir, ".tn");

  const rows = [];
  if (existsSync(root)) {
    const _NAME_RE = /^[a-zA-Z0-9_][a-zA-Z0-9_-]*$/;
    const names = [];
    for (const child of readdirSync(root)) {
      if (!_NAME_RE.test(child) && child !== "tn") continue;
      const yp = join(root, child, "tn.yaml");
      if (existsSync(yp)) names.push(child);
    }
    names.sort();
    for (const name of names) {
      const yp = join(root, name, "tn.yaml");
      let profile = "(unspecified)";
      try {
        const text = readFileSync(yp, "utf8");
        const m = text.match(/^\s+profile:\s*(\S+)/m);
        if (m) profile = m[1];
      } catch {
        // ignore
      }
      rows.push({ name, profile, yaml_path: yp });
    }
  }

  if (opts.format === "json") {
    process.stdout.write(JSON.stringify(rows, null, 2) + "\n");
    return;
  }
  if (rows.length === 0) {
    process.stdout.write(`(no ceremonies found under ${root})\n`);
    return;
  }
  const nameW = Math.max(4, ...rows.map((r) => r.name.length));
  const profW = Math.max(7, ...rows.map((r) => r.profile.length));
  process.stdout.write(
    `${"NAME".padEnd(nameW)}  ${"PROFILE".padEnd(profW)}  YAML\n`,
  );
  process.stdout.write(
    `${"-".repeat(nameW)}  ${"-".repeat(profW)}  ----\n`,
  );
  for (const r of rows) {
    process.stdout.write(
      `${r.name.padEnd(nameW)}  ${r.profile.padEnd(profW)}  ${r.yaml_path}\n`,
    );
  }
}

async function validateCmd() {
  // Static check of the project's .tn/ tree. Mirrors Python's
  // ``tn validate`` subcommand (python/tn/cli.py:cmd_validate).
  const rest = argv.slice(3);
  const opts = { projectDir: null };
  for (let i = 0; i < rest.length; i += 1) {
    if (rest[i] === "--project-dir") opts.projectDir = rest[++i];
  }
  const { existsSync, readdirSync, readFileSync } = await import("node:fs");
  const { join, resolve: pathResolve } = await import("node:path");
  const { parse: parseYaml } = await import("yaml");
  const { isKnownProfile, allProfileNames } = await import("../dist/profiles.js");

  const projectDir = opts.projectDir ? pathResolve(opts.projectDir) : process.cwd();
  const root = join(projectDir, ".tn");
  if (!existsSync(root)) {
    process.stdout.write(`(no .tn/ directory at ${projectDir} — nothing to validate)\n`);
    return;
  }

  const _NAME_RE = /^[a-zA-Z0-9_][a-zA-Z0-9_-]*$/;
  const names = [];
  for (const child of readdirSync(root)) {
    if (!_NAME_RE.test(child) && child !== "tn") continue;
    const yp = join(root, child, "tn.yaml");
    if (existsSync(yp)) names.push(child);
  }
  names.sort();
  if (names.length === 0) {
    process.stdout.write(`(no ceremonies under ${root} — nothing to validate)\n`);
    return;
  }

  const errors = [];
  const warnings = [];
  if (!names.includes("default")) {
    warnings.push(
      "no 'default' ceremony at .tn/default/. The project's identity " +
        "should live there; named streams normally extend from it.",
    );
  }

  for (const name of names) {
    const yp = join(root, name, "tn.yaml");
    let doc;
    try {
      const text = readFileSync(yp, "utf8");
      doc = parseYaml(text);
    } catch (e) {
      errors.push(`${yp}: read/parse failed: ${e.message}`);
      continue;
    }
    if (!doc || typeof doc !== "object") {
      errors.push(`${yp}: top-level must be a mapping`);
      continue;
    }
    const profile = (doc.ceremony ?? {}).profile;
    if (profile !== undefined && !isKnownProfile(profile)) {
      errors.push(
        `${yp}: unknown profile ${JSON.stringify(profile)}; ` +
          `catalog: ${JSON.stringify(allProfileNames())}`,
      );
    }
  }

  for (const w of warnings) process.stderr.write(`WARNING: ${w}\n`);
  if (errors.length > 0) {
    for (const e of errors) process.stderr.write(`ERROR: ${e}\n`);
    exit(1);
  }
  process.stdout.write(`OK: ${names.length} ceremon${names.length === 1 ? "y" : "ies"} valid.\n`);
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

async function adminCmd() {
  const sub = argv[3];
  const rest = argv.slice(4);
  const opts = {
    yaml: null,
    group: "default",
    out: null,
    did: null,
    leaf: null,
    groups: null,
    /** Set when --group / --groups was explicitly passed (vs the
     *  hard-coded default of "default") so `admin rotate` knows whether
     *  to expand to "all non-internal groups" or honor the user's choice. */
    groupSpecified: false,
  };
  for (let i = 0; i < rest.length; i += 1) {
    if (rest[i] === "--yaml") opts.yaml = rest[++i];
    else if (rest[i] === "--group") {
      opts.group = rest[++i];
      opts.groupSpecified = true;
    } else if (rest[i] === "--out") opts.out = rest[++i];
    else if (rest[i] === "--recipient-did") opts.did = rest[++i];
    else if (rest[i] === "--leaf") opts.leaf = Number.parseInt(rest[++i], 10);
    else if (rest[i] === "--groups") {
      opts.groups = rest[++i];
      opts.groupSpecified = true;
    }
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
    case "rotate": {
      // Resolve target groups. Unlike add-recipient/revoke-recipient
      // (which require an explicit --group), rotate defaults to "every
      // non-internal group in the ceremony" — the deploy-shaped flow.
      const cfg = rt.config;
      let targets;
      if (opts.groups) {
        targets = opts.groups.split(",").map((s) => s.trim()).filter(Boolean);
      } else if (opts.groupSpecified) {
        targets = [opts.group];
      } else {
        targets = [...cfg.groups.keys()].filter((g) => g !== "tn.agents");
      }
      const unknown = targets.filter((g) => !cfg.groups.has(g));
      if (unknown.length) {
        die(
          `admin rotate: unknown group(s) ${JSON.stringify(unknown)}; ` +
            `ceremony declares ${JSON.stringify([...cfg.groups.keys()].sort())}.`,
        );
      }

      // Snapshot surviving recipients PRE-rotation. (BTN keeps the
      // recipient list unchanged across rotation; reading the
      // snapshot here makes the intent explicit and survives any
      // future semantic change.)
      // Force a fresh log-replay first — each CLI invocation is a
      // distinct process, and the AdminStateCache's _refreshIfLogAdvanced
      // tripwire can stay stale across processes when the cache state
      // file lags the log. Explicit refresh() is cheap (the on-disk
      // log scan is the expensive part either way).
      rt.adminCache().refresh();
      const recipientGroups = new Map();
      for (const g of targets) {
        for (const rec of rt.recipients(g)) {
          if (rec.revoked) continue;
          const did = rec.recipientDid;
          if (typeof did !== "string") continue;
          const list = recipientGroups.get(did) ?? [];
          list.push(g);
          recipientGroups.set(did, list);
        }
      }

      // Rotate each group. NodeRuntime.rotateGroup mints a new
      // BtnPublisher, swaps the on-disk state + self-kit, bumps
      // groups.<g>.index_epoch in the yaml, and emits
      // tn.rotation.completed.
      const rotated = [];
      for (const g of targets) {
        const r = rt.rotateGroup(g);
        rotated.push({ group: g, generation: r.generation });
      }

      if (recipientGroups.size === 0) {
        stdout.write(
          JSON.stringify({
            ok: true,
            rotated,
            artifacts: [],
            note: "no surviving recipients to bundle for; rotation recorded",
          }) + "\n",
        );
        break;
      }

      // Resolve output destination. Mirrors `tn rotate` in Python:
      //   * absent           → ./rotated_<UTC_TS>/
      //   * existing dir / no-extension path → that dir
      //   * <something>.tnpkg + single recipient → that file
      //   * <something>.tnpkg + multi recipient → reject
      const tsStamp = new Date()
        .toISOString()
        .replace(/[-:]/g, "")
        .replace(/\..*$/, "Z");
      let outDir;
      let singleFile = null;
      if (!opts.out) {
        outDir = pathResolve(process.cwd(), `rotated_${tsStamp}`);
      } else {
        const resolved = pathResolve(process.cwd(), opts.out);
        if (resolved.endsWith(".tnpkg")) {
          if (recipientGroups.size > 1) {
            die(
              `admin rotate: --out ${opts.out} is a single .tnpkg path but ` +
                `this rotation has ${recipientGroups.size} surviving recipient(s). ` +
                `Pass a directory path (or omit --out) to write one .tnpkg per recipient.`,
            );
          }
          outDir = dirname(resolved);
          singleFile = resolved;
        } else {
          outDir = resolved;
        }
      }
      mkdirSync(outDir, { recursive: true });

      // Per recipient: re-mint kits across their groups (via
      // addRecipient, which uses the post-rotation publisher
      // state) and bundle into a kit_bundle .tnpkg the recipient
      // can absorb.
      const artifacts = [];
      for (const [did, groupList] of recipientGroups.entries()) {
        const safe = did.replace(/[^A-Za-z0-9._-]/g, "_");
        const pkgPath = singleFile ?? join(outDir, `${safe}.tnpkg`);
        const tmpDir = mkdtempSync(join(tmpdir(), "tn-rot-bundle-"));
        try {
          // Write fresh kits for this recipient into a temp staging
          // dir, then compile a kit_bundle from it. Using a temp
          // keystore (not the publisher's live one) avoids the
          // "ship the publisher's self-kit by accident" footgun
          // documented in the Python `bundle_for_recipient` path.
          for (const g of groupList) {
            const stagedKit = join(tmpDir, `${g}.btn.mykit`);
            rt.addRecipient(g, stagedKit, did);
          }
          const result = compileKitBundleToFile({
            keystoreDir: tmpDir,
            outPath: pkgPath,
            groups: groupList,
            label: `rotation@${tsStamp}`,
            full: false,
          });
          artifacts.push(result.outPath);
        } finally {
          rmSync(tmpDir, { recursive: true, force: true });
        }
      }

      stdout.write(
        JSON.stringify({
          ok: true,
          rotated,
          artifacts,
          out_dir: outDir,
        }) + "\n",
      );
      break;
    }
    default:
      die(
        `admin: unknown subcommand ${sub}. ` +
          "try add-recipient | revoke-recipient | revoked-count | rotate",
      );
  }
}

// ── init: bootstrap or attach to a ceremony ────────────────────────────
// Mirrors Python's `tn init <project>` (cmd_init). The positional is a
// PROJECT NAME, not a yaml path: it mints (or re-attaches to) a ROOT
// ceremony at `<projectDir>/.tn/<name>/tn.yaml` with its own keystore,
// admin log, and logs — the 0.5.0a2 flipped layout. The basename is the
// ceremony name; any leading path component is the project dir (so
// `tn-js init foo/bar` lands at `foo/.tn/bar/`).
//
//   tn-js init <name>        mint/attach root ceremony at .tn/<name>/, back up
//                            to the vault and print a claim URL
//   tn-js init <name> --no-link   mint only; no vault backup / claim URL
//   tn-js init <name> --link <url>  override the vault base URL
//   tn-js init --yaml <path> attach to an explicit yaml (back-compat)
//   tn-js init               discovery chain (./tn.yaml, ./.tn/default/)
//
// On a fresh mint (unless --no-link) this backs the ceremony up to the
// vault as a pending claim and prints a CLAIM URL the operator opens in a
// browser to attach the project to their account. Mirrors Python cmd_init.
//
// Prints a JSON receipt {ok, yaml_path, ceremony_id, did, claim_url?} to stdout.
async function initCmd() {
  const rest = argv.slice(3);
  let yamlPath = null;
  let projectArg = null;
  let noLink = false;
  let linkUrl = null;
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === "--yaml") yamlPath = rest[++i];
    else if (a === "--no-link") noLink = true;
    else if (a === "--link") linkUrl = rest[++i];
    else if (a === "-h" || a === "--help") {
      stdout.write(
        "tn-js init [<project-name>] [--yaml <yaml-path>] [--no-link] [--link <url>]\n" +
          "  Mint or attach to a TN ceremony. A <project-name> mints a root\n" +
          "  ceremony at <cwd>/.tn/<name>/ (own keystore + admin + logs) and,\n" +
          "  unless --no-link, backs it up to the vault and prints a claim URL.\n" +
          "  --link <url> overrides the vault base URL (default: TN_VAULT_URL\n" +
          "  or the hosted vault). --yaml attaches to an explicit yaml; no arg\n" +
          "  runs discovery (./tn.yaml -> ./.tn/default/tn.yaml).\n",
      );
      return;
    } else if (!a.startsWith("-") && projectArg === null) {
      projectArg = a;
    }
  }

  // Resolve the ceremony yaml. A bare project name flips into the
  // `.tn/<name>/` layout via an as-root mint (mirrors Python cmd_init's
  // `_ensure_ceremony_on_disk(name, as_root=True, project_dir=...)`).
  // ensureCeremonyOnDisk is idempotent — re-running attaches to the
  // existing ceremony instead of erroring.
  // Load-or-mint the machine-global device identity. Every flip-minted
  // ceremony is seeded from it so they share ONE device DID — the
  // precondition for warm-attach (a prior `account connect` mints that DID
  // onto the account; future inits reuse it). Mirrors Python's global
  // ~/.config/tn/identity.json model.
  const identity = Identity.loadOrMint();

  let resolvedYaml = yamlPath;
  let flipMint = false;
  let wasFresh = false;
  if (resolvedYaml === null && projectArg !== null) {
    if (/\.ya?ml$/i.test(projectArg)) {
      // Positional is an explicit yaml path — attach mode (back-compat).
      resolvedYaml = projectArg;
    } else {
      // Positional is a project name — flip into `.tn/<name>/` (root mint),
      // seeded from the global identity's device key.
      flipMint = true;
      const ceremonyName = basename(projectArg);
      const parent = dirname(projectArg);
      const projectDir = parent === "." ? process.cwd() : pathResolve(parent);
      const expectedYaml = join(projectDir, ".tn", ceremonyName, "tn.yaml");
      wasFresh = !existsSync(expectedYaml);
      resolvedYaml = ensureCeremonyOnDisk(ceremonyName, {
        projectDir,
        asRoot: true,
        devicePrivateBytes: identity.seed,
      });
    }
  }

  const tn = await tnInit(resolvedYaml ?? undefined);
  let did = null;
  let ceremonyId = null;
  try {
    const cfg = /** @type {Record<string, unknown>} */ (tn.config() ?? {});
    if (typeof cfg.ceremonyId === "string") ceremonyId = cfg.ceremonyId;
    const device = /** @type {Record<string, unknown> | undefined} */ (cfg.device);
    if (device && typeof device.device_identity === "string") did = device.device_identity;
  } catch {
    // Config readback is best-effort; init itself succeeded.
  }

  // Vault attach. Only on a fresh flip-mint, unless --no-link. Mirrors
  // Python cmd_init: a re-attach to an existing ceremony does NOT re-upload.
  //
  //   WARM path: if TN_API_KEY is set (wins) or the global identity already
  //   carries a linked_account_id, try to authenticate (DID-challenge — the
  //   device DID is a minted DID on the account) and attach the project
  //   directly via wallet.link. No browser, no claim URL.
  //
  //   COLD path: otherwise (or if warm-attach fails), mint a pending claim
  //   and print a CLAIM URL the operator opens in a browser.
  //
  // Failures warn but never fail init — the on-disk ceremony is still valid.
  let claimUrl = null;
  let attached = false;
  if (flipMint && wasFresh && !noLink) {
    const vaultBase = resolveVaultUrl(linkUrl ?? undefined);
    const warmSignal = process.env.TN_VAULT_API_KEY || process.env.TN_API_KEY || identity.linkedAccountId;
    if (warmSignal) {
      attached = await _tryWarmAttach(tn, resolvedYaml, identity, vaultBase);
    }
    if (!attached) {
      // Cold fallback: pending-claim + claim URL.
      try {
        const res = await tn.initUpload({ vaultBase });
        claimUrl = res.claimUrl;
        stdout.write(`\n[tn init] Backed up to ${vaultBase}\n`);
        stdout.write(`[tn init]   vault_id:   ${res.vaultId}\n`);
        stdout.write(`[tn init]   expires:    ${_formatExpiresLocal(res.expiresAt)}\n`);
        stdout.write(
          `\n[tn init] CLAIM URL - open this in your browser to attach the project to your account:\n`,
        );
        stdout.write(`  ${res.claimUrl}\n`);
        stdout.write(
          `\n[tn init] Already have a vault account, or want to attach this project later?\n`,
        );
        stdout.write(`[tn init]   1. Sign in at ${vaultBase}/account\n`);
        stdout.write(`[tn init]   2. On the Projects tab, mint a connect code\n`);
        stdout.write(`[tn init]   3. Run:  tn-js account connect <code> --yaml ${resolvedYaml}\n\n`);
      } catch (e) {
        stdout.write(`[tn init] WARN backup to vault failed: ${e?.message ?? e}\n`);
        stdout.write(`[tn init]   The ceremony at ${resolvedYaml} is still valid.\n`);
      }
    }
  }

  stdout.write(
    JSON.stringify({
      ok: true,
      yaml_path: resolvedYaml ?? "(discovery)",
      ceremony_id: ceremonyId,
      did,
      ...(claimUrl ? { claim_url: claimUrl } : {}),
      ...(attached ? { attached: true } : {}),
    }) + "\n",
  );
  await tnClose();
}

// Warm-attach: authenticate to the vault with the global device identity
// (DID-challenge — the device DID is a minted DID on the account after a
// prior `account connect`) and register the project directly via
// wallet.link. No browser, no claim URL. Returns true on success; false on
// any auth/link failure so the caller falls back to the cold claim-URL path.
// Mirrors Python's `_try_warm_attach`.
async function _tryWarmAttach(_tn, yamlPath, identity, vaultBase) {
  let client;
  try {
    const vid = vaultIdentityFromDeviceKey(identity.deviceKey());
    client = await VaultClient.forIdentity(vid, vaultBase);
  } catch (e) {
    stdout.write(
      `[tn init] WARN account auth failed (${e?.message ?? e}); using claim URL instead\n`,
    );
    return false;
  }
  try {
    const res = await WalletNamespace.link(client, yamlPath);
    stdout.write(`\n[tn init] Attached to your vault account (no browser needed).\n`);
    stdout.write(`[tn init]   project:    ${res.projectName}\n`);
    stdout.write(`[tn init]   project_id: ${res.projectId}\n`);
    stdout.write(`[tn init]   linked:     ${vaultBase}\n\n`);
    return true;
  } catch (e) {
    stdout.write(
      `[tn init] WARN account attach failed (${e?.message ?? e}); using claim URL instead\n`,
    );
    return false;
  } finally {
    try {
      client?.close?.();
    } catch {
      /* no-op */
    }
  }
}

// Render the vault's ISO-8601 UTC `expires_at` as local-time + tz label.
// Falls back to the raw ISO string on parse failure. Mirrors Python's
// _format_expires_local.
function _formatExpiresLocal(expiresIso) {
  try {
    const dt = new Date(expiresIso);
    if (Number.isNaN(dt.getTime())) return expiresIso;
    const pad = (n) => String(n).padStart(2, "0");
    const local =
      `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())} ` +
      `${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}`;
    // tz label from Intl when available, else numeric offset.
    let tz = "";
    try {
      const parts = new Intl.DateTimeFormat(undefined, { timeZoneName: "short" }).formatToParts(dt);
      tz = parts.find((p) => p.type === "timeZoneName")?.value ?? "";
    } catch {
      const off = -dt.getTimezoneOffset();
      const sign = off >= 0 ? "+" : "-";
      const abs = Math.abs(off);
      tz = `UTC${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`;
    }
    return `${local} ${tz}`.trim();
  } catch {
    return expiresIso;
  }
}

// ── vault: link / unlink — emits the corresponding log events ──────────
// Wraps tn.vault.link / tn.vault.unlink. These only emit log events
// (tn.vault.linked / tn.vault.unlinked); the yaml ceremony.mode flip is
// Python-only today (see VaultNamespace.setLinkState docstring).
async function vaultCmd() {
  const sub = argv[3];
  const rest = argv.slice(4);
  const opts = { yaml: null, vaultDid: null, projectId: null, reason: null };
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === "--yaml") opts.yaml = rest[++i];
    else if (a === "--reason") opts.reason = rest[++i];
    else if (!a.startsWith("-")) {
      if (opts.vaultDid === null) opts.vaultDid = a;
      else if (opts.projectId === null) opts.projectId = a;
    }
  }
  if (sub !== "link" && sub !== "unlink") {
    die(
      `vault: unknown subcommand ${sub}. try: vault link <vault-did> <project-id> [--yaml <path>]`,
    );
  }
  if (!opts.vaultDid || !opts.projectId) {
    die(`vault ${sub}: <vault-did> and <project-id> are required positionals`);
  }
  const tn = await tnInit(opts.yaml ?? undefined);
  try {
    const receipt =
      sub === "link"
        ? await tn.vault.link(opts.vaultDid, opts.projectId)
        : await tn.vault.unlink(opts.vaultDid, opts.projectId, opts.reason ?? undefined);
    stdout.write(
      JSON.stringify({
        ok: true,
        verb: `vault.${sub}`,
        event_id: receipt.eventId,
        row_hash: receipt.rowHash,
        vault_did: opts.vaultDid,
        project_id: opts.projectId,
      }) + "\n",
    );
  } finally {
    await tnClose();
  }
}

// ── show: read-only config inspection ──────────────────────────────────
// `show env` mirrors Python's `tn show env`: prints a JSON snapshot of the
// resolved ceremony configuration (me.did, ceremony.id/cipher/mode,
// keystore.path, handlers, public_fields).
async function showCmd() {
  const sub = argv[3];
  const rest = argv.slice(4);

  // show profiles: print the curated profile catalog. Wraps
  // cli/show_profiles.js. --format human (default) | json.
  if (sub === "profiles") {
    let format = "human";
    for (let i = 0; i < rest.length; i += 1) {
      if (rest[i] === "--format") format = rest[++i];
    }
    process.exitCode = await showProfilesCmd({ format });
    return;
  }

  let yamlPath = null;
  for (let i = 0; i < rest.length; i += 1) {
    if (rest[i] === "--yaml") yamlPath = rest[++i];
  }
  if (sub !== "env") {
    die(`show: unknown subcommand ${sub}. try: show env [--yaml <path>] | show profiles [--format human|json]`);
  }
  await tnInit(yamlPath ?? undefined);
  try {
    const cfg = tnConfig();
    // Pick only the safe summary fields. TS NodeRuntime exposes config with
    // its own field shape (camelCase, flatter than the yaml). Mirror the
    // documented `show env` contract: a stable JSON snapshot, not a raw dump.
    const c = /** @type {Record<string, unknown>} */ (cfg ?? {});
    const device = /** @type {Record<string, unknown> | undefined} */ (c.device);
    const handlers = /** @type {unknown[] | undefined} */ (c.handlers);
    const publicFields = c.publicFields;
    const publicFieldsCount = Array.isArray(publicFields)
      ? publicFields.length
      : publicFields && typeof publicFields === "object"
        ? Object.keys(publicFields).length
        : 0;
    stdout.write(
      JSON.stringify(
        {
          ok: true,
          me: { did: (device && typeof device === "object" && typeof device.device_identity === "string") ? device.device_identity : null },
          ceremony: {
            id: typeof c.ceremonyId === "string" ? c.ceremonyId : null,
            cipher: typeof c.cipher === "string" ? c.cipher : null,
            mode: typeof c.mode === "string" ? c.mode : null,
          },
          keystore: { path: typeof c.keystorePath === "string" ? c.keystorePath : null },
          logs: { path: typeof c.logPath === "string" ? c.logPath : null },
          handlers_count: Array.isArray(handlers) ? handlers.length : 0,
          public_fields_count: publicFieldsCount,
        },
        null,
        2,
      ) + "\n",
    );
  } finally {
    await tnClose();
  }
}

// ── wallet: link / unlink ──────────────────────────────────────────────
// Wraps WalletNamespace.link/unlink. Loads DeviceKey from the ceremony's
// keystore for vault auth; mutates ceremony.yaml to flip mode -> linked.
async function walletCmd() {
  const sub = argv[3];
  const rest = argv.slice(4);
  const opts = { yaml: null, vaultUrl: null, projectName: null, out: null, timeoutMs: null };
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === "--yaml") opts.yaml = rest[++i];
    else if (a === "--name" || a === "--project-name") opts.projectName = rest[++i];
    else if (a === "--vault") opts.vaultUrl = rest[++i];
    else if (a === "--out") opts.out = rest[++i];
    else if (a === "--timeout") opts.timeoutMs = Number(rest[++i]) * 1000;
    else if (!a.startsWith("-") && opts.vaultUrl === null) opts.vaultUrl = a;
  }

  // wallet sync: PULL inbox -> ABSORB each -> PUSH body. Wraps
  // cli/wallet_sync.js walletSyncCmd. Optional positional <yaml>; flags
  // --pull (stage only), --push-only, --drain-queue, --passphrase <p>,
  // --vault <url>. Mirrors Python `tn wallet sync`.
  if (sub === "sync") {
    const syncOpts = {};
    for (let i = 0; i < rest.length; i += 1) {
      const a = rest[i];
      if (a === "--yaml") syncOpts.yaml = rest[++i];
      else if (a === "--pull") syncOpts.pull = true;
      else if (a === "--push-only") syncOpts.pushOnly = true;
      else if (a === "--drain-queue") syncOpts.drainQueue = true;
      else if (a === "--passphrase") syncOpts.passphrase = rest[++i];
      else if (a === "--vault") syncOpts.vault = rest[++i];
      else if (!a.startsWith("-") && syncOpts.yaml === undefined) syncOpts.yaml = a;
      else die(`wallet sync: unknown arg ${a}`);
    }
    process.exitCode = await walletSyncCmd(syncOpts);
    return;
  }

  // wallet restore: multi-device restore via the browser loopback dance.
  // Prints a /restore URL; the operator opens it, the browser does the
  // passkey unwrap and POSTs the raw BEK back over loopback; we then fetch
  // + decrypt + write the keystore. Mirrors Python `tn wallet restore`.
  if (sub === "restore") {
    const vaultUrl = opts.vaultUrl || process.env.TN_VAULT_URL;
    if (!vaultUrl) die("wallet restore: --vault <url> (or TN_VAULT_URL) is required");
    if (!opts.out) die("wallet restore: --out <dir> is required");
    const loopOpts = {
      vaultUrl,
      outDir: opts.out,
      onRestoreUrl: (url) => {
        stdout.write("\n[tn wallet restore] Open this URL in your browser to authorize the restore:\n");
        stdout.write(`  ${url}\n\n`);
        stdout.write("[tn wallet restore] Waiting for the browser to deliver the unwrapped key...\n");
      },
    };
    if (opts.timeoutMs) loopOpts.timeoutMs = opts.timeoutMs;
    try {
      const res = await restoreViaLoopback(loopOpts);
      stdout.write(`\n[tn wallet restore] Restored ${res.filesWritten.length} file(s) to ${res.outDir}\n`);
      stdout.write(
        JSON.stringify({
          ok: true,
          verb: "wallet.restore",
          project_id: res.projectId,
          account_id: res.accountId,
          out_dir: res.outDir,
          files_written: res.filesWritten,
        }) + "\n",
      );
    } catch (e) {
      die(`wallet restore: ${e?.message ?? e}`);
    }
    return;
  }

  // wallet pull-prefs: refresh the global identity's account prefs from the
  // vault. Wraps cli/wallet_pull_prefs.js. --vault overrides the cached url.
  if (sub === "pull-prefs") {
    // `--help`/`-h` (and any bad flag) must print usage and exit cleanly,
    // never fall through to walletPullPrefsCmd (which dials the vault and
    // throws an uncaught fetch error when no host is reachable).
    if (rest.includes("--help") || rest.includes("-h")) {
      stdout.write("usage: tn wallet pull-prefs [--vault <url>]\n");
      return;
    }
    // --vault is the only flag this subcommand accepts; reject anything else
    // before we try to reach the vault so a typo fails fast and cleanly.
    for (let i = 0; i < rest.length; i += 1) {
      const a = rest[i];
      if (a === "--vault") {
        i += 1; // skip its value
        continue;
      }
      if (a.startsWith("-")) {
        die(
          `wallet pull-prefs: unknown flag ${a}. ` +
            `usage: tn wallet pull-prefs [--vault <url>]`,
        );
      }
    }
    process.exitCode = await walletPullPrefsCmd(
      opts.vaultUrl ? { vault: opts.vaultUrl } : {},
    );
    return;
  }

  // wallet export-mnemonic: re-display the stored BIP-39 recovery phrase.
  // Wraps cli/wallet_export_mnemonic.js. Requires --yes to show the phrase.
  if (sub === "export-mnemonic") {
    let yes = false;
    for (const a of rest) {
      if (a === "--yes") yes = true;
    }
    process.exitCode = await walletExportMnemonicCmd({ yes });
    return;
  }

  if (sub === "status") {
    // `tn-js wallet status [<yaml>]`
    // Positional yaml arg ends up in opts.vaultUrl (the generic positional slot);
    // --yaml <path> is also accepted for script use.
    const yamlArg = opts.yaml ?? opts.vaultUrl ?? null;
    const identityPath = defaultIdentityPath();
    if (!existsSync(identityPath)) {
      stdout.write(`No identity at ${identityPath}. Run \`tn init <project>\` first.\n`);
      return;
    }
    const identity = Identity.load(identityPath);
    stdout.write(`Identity: ${identity.did}\n`);
    stdout.write(`  file:    ${identity.path}\n`);
    stdout.write(`  linked:  ${identity.linkedVault ?? "(not linked)"}\n`);
    stdout.write(`  prefs:   default_new_ceremony_mode=${identity.prefs.defaultNewCeremonyMode}\n`);
    stdout.write(`           prefs_version=${identity.prefsVersion}\n`);
    if (yamlArg) {
      const yamlPath = pathResolve(yamlArg);
      if (!existsSync(yamlPath)) {
        stdout.write(`Ceremony: (no yaml at ${yamlPath})\n`);
        return;
      }
      const linkState = readLinkState(yamlPath);
      const tn = await tnInit(yamlPath);
      const cfg = /** @type {Record<string, unknown>} */ (tn.config() ?? {});
      await tnClose();
      /** @type {Map<string, unknown>} */
      const groups = cfg.groups instanceof Map ? cfg.groups : new Map();
      const pending = readSyncQueue(linkState.ceremonyId);
      stdout.write(`Ceremony: ${linkState.ceremonyId}\n`);
      stdout.write(`  yaml:            ${yamlPath}\n`);
      stdout.write(`  mode:            ${linkState.mode}\n`);
      stdout.write(`  cipher:          ${String(cfg.cipher ?? "btn")}\n`);
      stdout.write(`  linked_vault:    ${linkState.linkedVault || "(none)"}\n`);
      stdout.write(`  linked_project:  ${linkState.linkedProjectId || "(none)"}\n`);
      stdout.write(`  groups:          ${JSON.stringify([...groups.keys()])}\n`);
      if (pending.length > 0) {
        stdout.write(`  pending_sync:    ${pending.length} queued failure(s)\n`);
        const latest = pending[pending.length - 1];
        stdout.write(`    latest:        ${String(latest?.["error"] ?? "(no message)")}\n`);
        stdout.write(`    run:           tn wallet sync ${yamlArg} --drain-queue\n`);
      } else {
        stdout.write(`  pending_sync:    (queue empty)\n`);
      }
    }
    return;
  }

  if (sub === "unlink") {
    if (!opts.yaml) die("wallet unlink: --yaml <path> is required");
    WalletNamespace.unlink(opts.yaml);
    stdout.write(JSON.stringify({ ok: true, verb: "wallet.unlink", yaml: opts.yaml }) + "\n");
    return;
  }
  if (sub !== "link") {
    die(
      `wallet: unknown subcommand ${sub}. try: ` +
        `wallet status [<yaml>] | ` +
        `wallet sync [<yaml>] [--pull] [--push-only] [--drain-queue] [--passphrase <p>] [--vault <url>] | ` +
        `wallet link <vault-url> [--yaml <path>] [--name <project>] | ` +
        `wallet unlink --yaml <path> | ` +
        `wallet restore --vault <url> --out <dir> | ` +
        `wallet pull-prefs [--vault <url>] | ` +
        `wallet export-mnemonic [--yes]`,
    );
  }
  if (!opts.vaultUrl) die("wallet link: <vault-url> positional is required");
  if (!opts.yaml) die("wallet link: --yaml <path> is required");

  // Load DeviceKey from the ceremony's keystore so we can authenticate
  // against the vault as the same identity that owns the ceremony.
  const tn = await tnInit(opts.yaml);
  const cfg = /** @type {Record<string, unknown>} */ (tn.config() ?? {});
  await tnClose();
  const keystorePath = typeof cfg.keystorePath === "string" ? cfg.keystorePath : null;
  if (!keystorePath) die(`wallet link: ceremony at ${opts.yaml} has no keystorePath`);
  const ks = loadKeystore(keystorePath);

  const client = await VaultClient.forIdentity(vaultIdentityFromDeviceKey(ks.device), opts.vaultUrl);
  const linkOpts = {};
  if (opts.projectName) linkOpts.projectName = opts.projectName;
  try {
    const result = await WalletNamespace.link(client, opts.yaml, linkOpts);
    stdout.write(
      JSON.stringify({
        ok: true,
        verb: "wallet.link",
        project_id: result.projectId,
        project_name: result.projectName,
        vault_base_url: result.vaultBaseUrl,
        newly_linked: result.newlyLinked,
      }) + "\n",
    );
  } catch (e) {
    if (e instanceof VaultError) {
      die(`wallet link: ${e.message}${e.status !== null ? ` (status=${e.status})` : ""}`);
    }
    throw e;
  }
}

// ── account: connect ──────────────────────────────────────────────────
// Wraps AccountNamespace.connect. Loads DeviceKey from the ceremony's
// keystore; redeems the connect code against the vault; persists the
// resulting account binding into ceremony sync state.
async function accountCmd() {
  const sub = argv[3];
  const rest = argv.slice(4);
  const opts = { yaml: null, vaultUrl: null, code: null };
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === "--yaml") opts.yaml = rest[++i];
    else if (a === "--vault" || a === "--vault-url") opts.vaultUrl = rest[++i];
    else if (!a.startsWith("-") && opts.code === null) opts.code = a;
  }
  if (sub !== "connect") {
    die(`account: unknown subcommand ${sub}. try: account connect <code> [--vault <url>] [--yaml <path>]`);
  }
  if (!opts.code) die("account connect: <code> positional is required");
  if (!opts.yaml) die("account connect: --yaml <path> is required");

  const tn = await tnInit(opts.yaml);
  const cfg = /** @type {Record<string, unknown>} */ (tn.config() ?? {});
  await tnClose();
  const keystorePath = typeof cfg.keystorePath === "string" ? cfg.keystorePath : null;
  if (!keystorePath) die(`account connect: ceremony at ${opts.yaml} has no keystorePath`);
  const ks = loadKeystore(keystorePath);

  // Vault URL: explicit --vault > ceremony's linked_vault (from cfg) > error.
  let vaultUrl = opts.vaultUrl;
  if (!vaultUrl) {
    const ceremony = /** @type {Record<string, unknown> | undefined} */ (cfg.ceremony);
    const linked = ceremony && typeof ceremony.linked_vault === "string" ? ceremony.linked_vault : null;
    vaultUrl = linked || null;
  }
  if (!vaultUrl) {
    die("account connect: --vault <url> required (ceremony has no linked_vault to fall back to)");
  }

  try {
    const result = await AccountNamespace.connect(opts.code, vaultUrl, ks.device, { yamlPath: opts.yaml });

    // Stamp the account binding onto the machine-global identity so future
    // `tn-js init <name>` runs warm-attach to this account automatically
    // (no browser). Mirrors Python cmd_account_connect persisting
    // identity.linked_account_id. Best-effort: a stamp failure must not
    // fail the connect (the per-ceremony sync-state binding already
    // succeeded inside AccountNamespace.connect).
    let globalStamped = false;
    try {
      const identity = Identity.loadOrMint();
      if (identity.linkedAccountId !== result.accountId || identity.linkedVault !== vaultUrl) {
        identity.linkedAccountId = result.accountId;
        identity.linkedVault = vaultUrl;
        identity.save();
      }
      globalStamped = true;
    } catch (e) {
      stdout.write(`[account connect] WARN could not stamp global identity: ${e?.message ?? e}\n`);
    }

    stdout.write(
      JSON.stringify({
        ok: true,
        verb: "account.connect",
        account_id: result.accountId,
        did: result.did,
        project_id: result.projectId ?? null,
        project_name: result.projectName ?? null,
        global_identity_stamped: globalStamped,
      }) + "\n",
    );
  } catch (e) {
    if (e instanceof AccountConnectError) {
      die(`account connect: ${e.message}${e.status !== null ? ` (status=${e.status})` : ""}`);
    }
    throw e;
  }
}

// ── bundle: mint a kit_bundle .tnpkg for one recipient ─────────────────
// Wraps cli/bundle.js bundleCmd. Positionals: <recipient> <out>.
//   tn-js bundle <recipient> <out> [--yaml <path>] [--groups a,b]
//                [--seal-for-recipient]
async function bundleCliCmd() {
  const rest = argv.slice(3);
  const opts = {
    recipientIdentity: null,
    out: null,
    yaml: undefined,
    groups: undefined,
    sealForRecipient: false,
  };
  const positionals = [];
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === "--yaml") opts.yaml = rest[++i];
    else if (a === "--groups") opts.groups = rest[++i];
    else if (a === "--seal-for-recipient") opts.sealForRecipient = true;
    else if (!a.startsWith("-")) positionals.push(a);
    else die(`bundle: unknown arg ${a}`);
  }
  opts.recipientIdentity = positionals[0] ?? null;
  opts.out = positionals[1] ?? null;
  if (!opts.recipientIdentity || !opts.out) {
    die("bundle: <recipient> and <out> positionals are required");
  }
  process.exitCode = await bundleCmd(opts);
}

// ── add_recipient: one-shot mint + bundle for a group/recipient ────────
// Wraps cli/add_recipient.js addRecipientCmd. Positionals: <group> <recipient>.
//   tn-js add_recipient <group> <recipient> [--out <path>] [--yaml <path>]
//                       [--seal-for-recipient]
async function addRecipientCliCmd() {
  const rest = argv.slice(3);
  const opts = {
    group: null,
    recipient: null,
    out: undefined,
    yaml: undefined,
    sealForRecipient: false,
  };
  const positionals = [];
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === "--out") opts.out = rest[++i];
    else if (a === "--yaml") opts.yaml = rest[++i];
    else if (a === "--seal-for-recipient") opts.sealForRecipient = true;
    else if (!a.startsWith("-")) positionals.push(a);
    else die(`add_recipient: unknown arg ${a}`);
  }
  opts.group = positionals[0] ?? null;
  opts.recipient = positionals[1] ?? null;
  if (!opts.group || !opts.recipient) {
    die("add_recipient: <group> and <recipient> positionals are required");
  }
  process.exitCode = await addRecipientCmd(opts);
}

// ── absorb: install a .tnpkg into the active ceremony ──────────────────
// Wraps cli/absorb.js absorbCmd. Positional: <package>.
//   tn-js absorb <package> [--yaml <path>] [--allow-self-absorb]
async function absorbCliCmd() {
  const rest = argv.slice(3);
  const opts = { packagePath: null, yaml: undefined, allowSelfAbsorb: false };
  const positionals = [];
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === "--yaml") opts.yaml = rest[++i];
    else if (a === "--allow-self-absorb") opts.allowSelfAbsorb = true;
    else if (!a.startsWith("-")) positionals.push(a);
    else die(`absorb: unknown arg ${a}`);
  }
  opts.packagePath = positionals[0] ?? null;
  if (!opts.packagePath) die("absorb: <package> positional is required");
  process.exitCode = await absorbCmd(opts);
}

// ── group: post-init group management ──────────────────────────────────
// Wraps cli/group_add.js groupAddCmd under the `add` subcommand.
//   tn-js group add <name> [--fields a,b,c] [--cipher btn|jwe] [--yaml <path>]
async function groupCmd() {
  const sub = argv[3];
  if (sub !== "add") {
    die(`group: unknown subcommand ${sub}. try: group add <name> [--fields a,b] [--cipher btn|jwe] [--yaml <path>]`);
  }
  const rest = argv.slice(4);
  const opts = { name: null, fields: undefined, cipher: undefined, yaml: undefined };
  const positionals = [];
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === "--fields") opts.fields = rest[++i];
    else if (a === "--cipher") opts.cipher = rest[++i];
    else if (a === "--yaml") opts.yaml = rest[++i];
    else if (!a.startsWith("-")) positionals.push(a);
    else die(`group add: unknown arg ${a}`);
  }
  opts.name = positionals[0] ?? null;
  if (!opts.name) die("group add: <name> positional is required");
  process.exitCode = await groupAddCmd(opts);
}

// ── firehose: gated firehose-worker diagnostic probes ──────────────────
// Wraps cli/firehose.js firehoseCmd (stats|list|get).
//   tn-js firehose stats <tenant>
//   tn-js firehose list  <tenant> [--did <did>]
//   tn-js firehose get   <tenant> <ceremony> <name> [--did <did>] [--out <path>]
async function firehoseCliCmd() {
  const sub = argv[3];
  if (sub !== "stats" && sub !== "list" && sub !== "get") {
    die(`firehose: unknown subcommand ${sub}. try: firehose stats|list|get`);
  }
  const rest = argv.slice(4);
  const opts = { did: undefined, out: undefined };
  const positionals = [];
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === "--did") opts.did = rest[++i];
    else if (a === "--out") opts.out = rest[++i];
    else if (!a.startsWith("-")) positionals.push(a);
    else die(`firehose ${sub}: unknown arg ${a}`);
  }
  if (sub === "stats") {
    if (!positionals[0]) die("firehose stats: <tenant> positional is required");
    opts.tenant = positionals[0];
  } else if (sub === "list") {
    if (!positionals[0]) die("firehose list: <tenant> positional is required");
    opts.tenant = positionals[0];
  } else {
    if (!positionals[0] || !positionals[1] || !positionals[2]) {
      die("firehose get: <tenant> <ceremony> <name> positionals are required");
    }
    opts.tenant = positionals[0];
    opts.ceremony = positionals[1];
    opts.name = positionals[2];
  }
  try {
    process.exitCode = await firehoseCmd(sub, opts);
  } catch (e) {
    // firehoseCmd's _die throws a FirehoseExit carrying the exit code
    // (the stderr message was already written by the handler).
    if (e && typeof e.code === "number") {
      process.exitCode = e.code;
    } else {
      throw e;
    }
  }
}

// ── inbox: local invitation handling (no vault contact) ────────────────
// Wraps cli/inbox_accept.js inboxAcceptCmd and cli/inbox_list_local.js
// inboxListLocalCmd under the `accept` / `list-local` subcommands.
//   tn-js inbox accept <zip> [--yaml <path>]
//   tn-js inbox list-local [--dir <path>]
async function inboxCmd() {
  const sub = argv[3];
  const rest = argv.slice(4);
  if (sub === "accept") {
    const opts = { zipPath: null, yaml: undefined };
    const positionals = [];
    for (let i = 0; i < rest.length; i += 1) {
      const a = rest[i];
      if (a === "--yaml") opts.yaml = rest[++i];
      else if (!a.startsWith("-")) positionals.push(a);
      else die(`inbox accept: unknown arg ${a}`);
    }
    opts.zipPath = positionals[0] ?? null;
    if (!opts.zipPath) die("inbox accept: <zip> positional is required");
    process.exitCode = await inboxAcceptCmd(opts);
    return;
  }
  if (sub === "list-local") {
    const opts = { dir: undefined };
    for (let i = 0; i < rest.length; i += 1) {
      const a = rest[i];
      if (a === "--dir") opts.dir = rest[++i];
      else die(`inbox list-local: unknown arg ${a}`);
    }
    process.exitCode = await inboxListLocalCmd(opts);
    return;
  }
  die(
    `inbox: unknown subcommand ${sub}. try: ` +
      `inbox accept <zip> [--yaml <path>] | inbox list-local [--dir <path>]`,
  );
}

const cmd = argv[2];
switch (cmd) {
  case "init":
    await initCmd();
    break;
  case "vault":
    await vaultCmd();
    break;
  case "wallet":
    await walletCmd();
    break;
  case "account":
    await accountCmd();
    break;
  case "show":
    await showCmd();
    break;
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
    await adminCmd();
    break;
  case "compile":
    compileCmd();
    break;
  case "bundle":
    await bundleCliCmd();
    break;
  case "add_recipient":
    await addRecipientCliCmd();
    break;
  case "absorb":
    await absorbCliCmd();
    break;
  case "group":
    await groupCmd();
    break;
  case "firehose":
    await firehoseCliCmd();
    break;
  case "inbox":
    await inboxCmd();
    break;
  case "watch":
    await watchCmd();
    break;
  case "streams":
    await streamsCmd();
    break;
  case "validate":
    await validateCmd();
    break;
  case undefined:
  case "--help":
  case "-h":
    process.stderr.write(
      "tn-js <init|wallet|account|vault|show|seal|verify|canonical|info|read|watch|streams|validate|compile|admin|bundle|add_recipient|absorb|group|firehose|inbox>\n" +
        "  init       [<yaml-path>] — initialize / attach to a ceremony, print receipt JSON\n" +
        "  wallet status [<yaml>]\n" +
        "             print identity + optional ceremony details\n" +
        "  wallet sync [<yaml>] [--pull] [--push-only] [--drain-queue] [--passphrase <p>] [--vault <url>]\n" +
        "             two-way sync: pull account inbox + absorb, then push the body backup\n" +
        "             (--pull stages only; --push-only / --drain-queue skip the pull/absorb)\n" +
        "  wallet link <vault-url> --yaml <path> [--name <project>]\n" +
        "             create vault project + flip ceremony.mode to linked\n" +
        "  wallet unlink --yaml <path>\n" +
        "             flip ceremony.mode back to local (yaml-only; vault project untouched)\n" +
        "  wallet pull-prefs [--vault <url>]\n" +
        "             refresh the global identity's account prefs from the vault\n" +
        "  wallet export-mnemonic [--yes]\n" +
        "             re-display the stored BIP-39 recovery phrase (--yes to confirm)\n" +
        "  account connect <code> --yaml <path> [--vault <url>]\n" +
        "             redeem a vault connect code; binds device DID to the account\n" +
        "             and persists account_id into ceremony sync state\n" +
        "  vault link <vault-did> <project-id> [--yaml <path>]\n" +
        "             emit tn.vault.linked event into the ceremony's log\n" +
        "  vault unlink <vault-did> <project-id> [--reason <text>] [--yaml <path>]\n" +
        "             emit tn.vault.unlinked event into the ceremony's log\n" +
        "  show env   [--yaml <path>] — print resolved ceremony config as JSON\n" +
        "  show profiles [--format human|json] — print the curated profile catalog\n" +
        "  seal       stdin JSON -> ndjson envelope line on stdout\n" +
        "  verify     ndjson envelope line -> {ok, ...} on stdout\n" +
        "  canonical  stdin JSON -> canonical UTF-8 line on stdout\n" +
        "  info       --yaml <path> --event <type> [--level info] --field k=v ...\n" +
        "             Append one attested entry to the log defined in yaml.\n" +
        "  read       --yaml <path> [--log <path>] [--compact]\n" +
        "             Iterate decoded entries as pretty JSON on stdout.\n" +
        "             Includes plaintext (per-group) and valid {signature,rowHash,chain}.\n" +
        "             --compact: one JSON line per entry instead of pretty-print.\n" +
        "  watch      --yaml <path> [--since start|now|<seq>|<iso-ts>] [--verify] [--poll <ms>] [--once]\n" +
        "             Tail the log and write one decoded entry per line to stdout.\n" +
        "             --since controls the starting point (default: now, only new appends).\n" +
        "             --once: snapshot mode — dump matching entries and exit.\n" +
        "             --verify: include signature/rowHash/chain validity in output.\n" +
        "             --poll <ms>: polling interval in ms (default: 300).\n" +
        "  admin add-recipient     --yaml <path> [--group default] --out <kit-path>\n" +
        "                          [--recipient-did did:key:...]\n" +
        "  admin revoke-recipient  --yaml <path> [--group default] --leaf <index>\n" +
        "                          [--recipient-did did:key:...]\n" +
        "  admin revoked-count     --yaml <path> [--group default]\n" +
        "  admin rotate            --yaml <path> [--group <g> | --groups a,b,c]\n" +
        "                          [--out <dir>|<file.tnpkg>]\n" +
        "                          The deploy primitive — rotates each target group\n" +
        "                          (default: every non-internal group), bumps\n" +
        "                          index_epoch in the yaml, and emits one\n" +
        "                          .tnpkg per surviving recipient under\n" +
        "                          ./rotated_<UTC_TS>/ (or --out).\n" +
        "  compile    --keystore <dir>  --out <file.tnpkg>  [--kit <group>]... [--label <text>] [--full]\n" +
        "             Package *.btn.mykit files into a .tnpkg (zip w/ manifest.json + kits) that the\n" +
        "             Chrome extension, Python SDK, and tn-js can all import.\n" +
        "             --kit filters to named groups; --full also writes publisher state + signing seed.\n" +
        "             --yaml <path> may be used in place of --keystore to infer the keystore dir.\n" +
        "  bundle     <recipient> <out> [--yaml <path>] [--groups a,b] [--seal-for-recipient]\n" +
        "             Mint a kit_bundle .tnpkg for one recipient DID.\n" +
        "  add_recipient <group> <recipient> [--out <path>] [--yaml <path>] [--seal-for-recipient]\n" +
        "             One-shot mint + bundle a reader kit for a group/recipient.\n" +
        "  absorb     <package> [--yaml <path>] [--allow-self-absorb]\n" +
        "             Install a .tnpkg (kit bundle, enrolment) into the active ceremony.\n" +
        "  group add  <name> [--fields a,b,c] [--cipher btn|jwe] [--yaml <path>]\n" +
        "             Add a group to an existing ceremony post-init.\n" +
        "  firehose stats|list|get ...  (gated; needs TN_FIREHOSE_URL + token)\n" +
        "             firehose stats <tenant>\n" +
        "             firehose list  <tenant> [--did <did>]\n" +
        "             firehose get   <tenant> <ceremony> <name> [--did <did>] [--out <path>]\n" +
        "  inbox accept <zip> [--yaml <path>]\n" +
        "             accept an invitation zip locally and install the kit it carries.\n" +
        "  inbox list-local [--dir <path>]\n" +
        "             list downloaded tn-invite-*.zip files (default ~/Downloads); no vault contact.\n",
    );
    exit(cmd ? 0 : 1);
    break;
  default:
    die(`unknown command: ${cmd}`);
}
