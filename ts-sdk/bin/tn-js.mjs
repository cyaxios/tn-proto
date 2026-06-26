#!/usr/bin/env node
// Minimal Node CLI for TN.
//
// Subcommands:
//
//   tn-js seal < seal-input.json > envelope.ndjson
//   tn-js verify < envelope.ndjson
//   tn-js watch --yaml ./tn.yaml [--since start|now|<seq>|<iso-ts>] [--verify] [--interval <seconds>] [--poll <ms>] [--once]
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

import { argv, exit } from "node:process";

import { bundleCmd } from "../dist/cli/bundle.js";
import { addRecipientCmd } from "../dist/cli/add_recipient.js";
import { absorbCmd } from "../dist/cli/absorb.js";
import { groupAddCmd } from "../dist/cli/group_add.js";
import { firehoseCmd, firehoseEnabled } from "../dist/cli/firehose.js";
import { inboxAcceptCmd } from "../dist/cli/inbox_accept.js";
import { inboxListLocalCmd } from "../dist/cli/inbox_list_local.js";
import { sealCmd } from "../dist/cli/seal.js";
import { verifyCmd } from "../dist/cli/verify.js";
import { canonicalCmd } from "../dist/cli/canonical.js";
import { infoCmd } from "../dist/cli/info.js";
import { readCmd } from "../dist/cli/read.js";
import { compileCmd } from "../dist/cli/compile.js";
import { exportCmd } from "../dist/cli/export.js";
import { importCmd } from "../dist/cli/import.js";
import { streamsCmd } from "../dist/cli/streams.js";
import { validateCmd } from "../dist/cli/validate.js";
import { watchCmd } from "../dist/cli/watch.js";
import { adminCmd } from "../dist/cli/admin.js";
import { initCmd } from "../dist/cli/init.js";
import { vaultCmd } from "../dist/cli/vault.js";
import { showCmd } from "../dist/cli/show.js";
import { walletCmd } from "../dist/cli/wallet.js";
import { accountCmd } from "../dist/cli/account.js";
import { authCmd } from "../dist/cli/auth.js";

function die(msg) {
  process.stderr.write(`tn-js: ${msg}\n`);
  exit(2);
}

// ── Thin wrappers over the typed src/cli/* command modules: parse argv into
// the module's typed options, then delegate. The module does the work and
// returns the process exit code (mirrors the bundle/add_recipient wrappers). ─
function infoCliCmd() {
  const rest = argv.slice(3);
  const opts = { yaml: null, event: null, level: "info", fields: {}, json: false };
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === "--yaml") opts.yaml = rest[++i];
    else if (a === "--event") opts.event = rest[++i];
    else if (a === "--level") opts.level = rest[++i];
    else if (a === "--json") opts.json = true;
    else if (a === "--field") {
      const [k, ...v] = rest[++i].split("=");
      opts.fields[k] = v.join("=");
    } else if (a === "--int") {
      const [k, v] = rest[++i].split("=");
      opts.fields[k] = Number.parseInt(v, 10);
    } else if (a === "--bool") {
      const [k, v] = rest[++i].split("=");
      opts.fields[k] = v === "true";
    }
  }
  if (!opts.yaml) die("info: --yaml <path> is required");
  if (!opts.event) die("info: --event <type> is required");
  process.exitCode = infoCmd(opts);
}

function readCliCmd() {
  const rest = argv.slice(3);
  // Parity with Python `tn read [<log>]`: positional <log> (stream name or
  // path), --yaml optional (discovered), --all-runs/--no-all-runs (default on).
  const opts = { yaml: undefined, log: undefined, json: false, compact: false, allRuns: true };
  const positionals = [];
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === "--yaml") opts.yaml = rest[++i];
    else if (a === "--log") opts.log = rest[++i];
    else if (a === "--json") opts.json = true;
    else if (a === "--compact") opts.compact = true;
    else if (a === "--all-runs") opts.allRuns = true;
    else if (a === "--no-all-runs") opts.allRuns = false;
    else if (!a.startsWith("-")) positionals.push(a);
    else die(`read: unknown arg ${a}`);
  }
  // The positional <log> takes precedence over --log (both name a stream/path).
  if (positionals[0] !== undefined) opts.log = positionals[0];
  process.exitCode = readCmd(opts);
}

function compileCliCmd() {
  const rest = argv.slice(3);
  const opts = {
    keystore: undefined,
    yaml: undefined,
    out: null,
    label: undefined,
    kits: [],
    full: false,
  };
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
  process.exitCode = compileCmd(opts);
}

async function exportCliCmd() {
  const rest = argv.slice(3);
  const opts = { yaml: undefined, out: undefined, kind: undefined, includeSecrets: false, json: false };
  for (let i = 0; i < rest.length; i += 1) {
    if (rest[i] === "--yaml") opts.yaml = rest[++i];
    else if (rest[i] === "--out") opts.out = rest[++i];
    else if (rest[i] === "--kind") opts.kind = rest[++i];
    else if (rest[i] === "--include-secrets") opts.includeSecrets = true;
    else if (rest[i] === "--json") opts.json = true;
  }
  process.exitCode = await exportCmd(opts);
}

function importCliCmd() {
  const rest = argv.slice(3);
  const opts = { packagePath: undefined, cwd: undefined, json: false };
  for (let i = 0; i < rest.length; i += 1) {
    if (rest[i] === "--cwd") opts.cwd = rest[++i];
    else if (rest[i] === "--json") opts.json = true;
    else if (!rest[i].startsWith("--")) opts.packagePath = rest[i];
  }
  process.exitCode = importCmd(opts);
}

async function streamsCliCmd() {
  const rest = argv.slice(3);
  const opts = { projectDir: null, format: "human" };
  for (let i = 0; i < rest.length; i += 1) {
    if (rest[i] === "--project-dir") opts.projectDir = rest[++i];
    else if (rest[i] === "--format") opts.format = rest[++i];
  }
  process.exitCode = await streamsCmd(opts);
}

async function validateCliCmd() {
  const rest = argv.slice(3);
  const opts = { projectDir: null };
  for (let i = 0; i < rest.length; i += 1) {
    if (rest[i] === "--project-dir") opts.projectDir = rest[++i];
  }
  process.exitCode = await validateCmd(opts);
}

async function watchCliCmd() {
  const args = argv.slice(3);
  // Default poll: 300ms == Python's --interval default of 0.3 seconds.
  const opts = { yamlPath: null, since: "now", verify: false, pollMs: 300, once: false };
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === "--yaml") opts.yamlPath = args[++i];
    else if (a === "--since") opts.since = args[++i];
    else if (a === "--verify") opts.verify = true;
    // --interval <seconds> is the canonical flag (parity with Python). Convert
    // seconds -> ms for the internal pollMs representation.
    else if (a === "--interval") opts.pollMs = Number(args[++i]) * 1000;
    // --poll <ms> is kept as a back-compat alias (still milliseconds).
    else if (a === "--poll") opts.pollMs = Number(args[++i]);
    else if (a === "--once") opts.once = true;
    else die(`watch: unknown arg ${a}`);
  }
  process.exitCode = await watchCmd(opts);
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
    die(
      `group: unknown subcommand ${sub}. try: group add <name> [--fields a,b] [--cipher btn|jwe] [--yaml <path>]`,
    );
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
    process.exitCode = await initCmd(argv);
    break;
  case "vault":
    process.exitCode = await vaultCmd(argv);
    break;
  case "wallet":
    process.exitCode = await walletCmd(argv);
    break;
  case "account":
    process.exitCode = await accountCmd(argv);
    break;
  case "auth":
    process.exitCode = await authCmd(argv);
    break;
  case "show":
    process.exitCode = await showCmd(argv);
    break;
  case "seal":
    process.exitCode = await sealCmd();
    break;
  case "verify":
    process.exitCode = await verifyCmd();
    break;
  case "canonical":
    process.exitCode = await canonicalCmd();
    break;
  case "info":
    infoCliCmd();
    break;
  case "read":
    readCliCmd();
    break;
  case "admin":
    process.exitCode = await adminCmd(argv);
    break;
  case "compile":
    compileCliCmd();
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
    // Gated like Python (_firehose_enabled / _register_firehose_subcommands):
    // when TN_FIREHOSE_ENABLED!=1 the verb is unmounted, so dispatch falls
    // through to the unknown-command path (die -> exit 2).
    if (!firehoseEnabled()) {
      die(`unknown command: ${cmd}`);
    }
    await firehoseCliCmd();
    break;
  case "inbox":
    await inboxCmd();
    break;
  case "watch":
    await watchCliCmd();
    break;
  case "streams":
    await streamsCliCmd();
    break;
  case "validate":
    await validateCliCmd();
    break;
  case "export":
    await exportCliCmd();
    break;
  case "import":
    importCliCmd();
    break;
  case undefined:
  case "--help":
  case "-h": {
    // firehose is gated like Python: only listed when TN_FIREHOSE_ENABLED=1.
    const fhEnabled = firehoseEnabled();
    const topVerbs =
      "tn-js <init|wallet|account|vault|show|seal|verify|canonical|info|read|watch|streams|validate|compile|admin|bundle|add_recipient|absorb|export|import|group|" +
      (fhEnabled ? "firehose|" : "") +
      "inbox>\n";
    const firehoseHelp = fhEnabled
      ? "  firehose stats|list|get ...  (gated; needs TN_FIREHOSE_URL + token)\n" +
        "             firehose stats <tenant>\n" +
        "             firehose list  <tenant> [--did <did>]\n" +
        "             firehose get   <tenant> <ceremony> <name> [--did <did>] [--out <path>]\n"
      : "";
    process.stderr.write(
      topVerbs +
        "  init       [<project-name>] [--no-link] [--link <url>] [--force] [--cipher btn]\n" +
        "             [--version-name <name>] [--json]\n" +
        "             Mint or attach to a ceremony. No name uses the current folder.\n" +
        "             Human output by default; --json prints the receipt.\n" +
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
        "  account connect <code> --yaml <path> [--vault <url>] [--passphrase <p>] [--json]\n" +
        "             redeem a vault connect code; binds device DID to the account\n" +
        "             and persists account_id into ceremony sync state. --passphrase\n" +
        "             caches the account AWK so future inits back up the body unattended\n" +
        "  vault link <vault-did> <project-id> [--yaml <path>]\n" +
        "             emit tn.vault.linked event into the ceremony's log\n" +
        "  vault unlink <vault-did> <project-id> [--reason <text>] [--yaml <path>]\n" +
        "             emit tn.vault.unlinked event into the ceremony's log\n" +
        "  show env   [--yaml <path>] [--format human|json] [--json] — print resolved ceremony config (human default)\n" +
        "  show profiles [--format human|json] — print the curated profile catalog\n" +
        "  seal       stdin JSON -> ndjson envelope line on stdout\n" +
        "  verify     ndjson envelope line -> {ok, ...} on stdout\n" +
        "  canonical  stdin JSON -> canonical UTF-8 line on stdout\n" +
        "  info       --yaml <path> --event <type> [--level info] [--json] --field k=v ...\n" +
        "             Append one attested entry to the log defined in yaml.\n" +
        "             Human confirmation by default; --json prints the receipt.\n" +
        "  read       [<log>] [--yaml <path>] [--json] [--compact] [--no-all-runs]\n" +
        "             Print decoded entries; human one-line-per-entry by default.\n" +
        "             <log> is a stream/ceremony name (resolved from .tn/<name>/) or a\n" +
        "             literal log path; --yaml is discovered when omitted.\n" +
        "             --json: structured envelope shape (pretty; plaintext + valid).\n" +
        "             --compact: one JSON line per entry (implies --json).\n" +
        "             --no-all-runs: restrict to this process' run (default: all runs).\n" +
        "  watch      --yaml <path> [--since start|now|<seq>|<iso-ts>] [--verify] [--interval <seconds>] [--once]\n" +
        "             Tail the log and write one decoded entry per line to stdout.\n" +
        "             --since controls the starting point (default: now, only new appends).\n" +
        "             --once: snapshot mode — dump matching entries and exit.\n" +
        "             --verify: include signature/rowHash/chain validity in output.\n" +
        "             --interval <seconds>: poll interval in seconds (default: 0.3).\n" +
        "             --poll <ms>: back-compat alias for the interval, in milliseconds.\n" +
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
        "             Install a received .tnpkg (kit bundle, enrolment) INTO the\n" +
        "             existing ceremony at --yaml. To START a ceremony from a\n" +
        "             downloaded seed, use `import` instead.\n" +
        "  export     --kind project_seed --out <file> --include-secrets [--yaml <path>] [--json]\n" +
        "             Mint a project_seed .tnpkg (tn.yaml + raw keystore) to carry to\n" +
        "             another device. Restore it there with `tn-js import`.\n" +
        "             Human summary by default; --json prints the receipt.\n" +
        "  import     <package> [--cwd <dir>] [--json]\n" +
        "             Bootstrap a ceremony from a downloaded project_seed .tnpkg: writes\n" +
        "             tn.yaml + keystore into the cwd and makes it live. The 'carry a\n" +
        "             seed to a new device' entry point.\n" +
        "  group add  <name> [--fields a,b,c] [--cipher btn|jwe] [--yaml <path>]\n" +
        "             Add a group to an existing ceremony post-init.\n" +
        firehoseHelp +
        "  inbox accept <zip> [--yaml <path>]\n" +
        "             accept an invitation zip locally and install the kit it carries.\n" +
        "  inbox list-local [--dir <path>]\n" +
        "             list downloaded tn-invite-*.zip files (default ~/Downloads); no vault contact.\n",
    );
    exit(cmd ? 0 : 1);
    break;
  }
  default:
    die(`unknown command: ${cmd}`);
}
