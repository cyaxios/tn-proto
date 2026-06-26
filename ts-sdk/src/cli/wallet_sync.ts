// Top-level `tn wallet sync` CLI verb — TypeScript parity port of Python's
// `cmd_wallet_sync` plus its helpers `_pull_absorb_step`,
// `_stage_account_inbox`, and `_cmd_wallet_sync_pull`. Behaviour, flags,
// stdout, and exit codes mirror the Python verb.
//
//   tn wallet sync                # PULL inbox -> ABSORB each -> PUSH body
//   tn wallet sync --pull         # STAGE the account inbox only (no absorb)
//   tn wallet sync --push-only    # skip pull/absorb, push the body backup
//   tn wallet sync --drain-queue  # skip pull/absorb, retry the push
//
// CRITICAL - supported AWK/BEK whole-body model, NOT the
// deprecated per-file wallet-passphrase sealing. The PUSH packs the
// ceremony body (keystore files + tn.yaml) into a STORED zip, AES-256-GCM
// encrypts it as a no-AAD `nonce||ct` frame under the project BEK (mint +
// wrap a fresh BEK when the project has none, else derive it from the
// account passphrase), and PUTs the frame to encrypted-blob-account with
// If-Match. This is the exact inverse of the restore side
// (`restore.ts::decryptBlobWithBek`, which reads `ciphertext_b64` as the
// whole frame) — so a body pushed here round-trips through `tn wallet
// restore --passphrase`. The pull/absorb merge runs first so a revocation
// another device/publisher made is merged into local state before the push,
// and an INFORMED leaf-reuse (equivocation) re-add is surfaced.
//
// Like the other CLI verbs (absorb.ts, wallet_pull_prefs.ts) this owns no
// argv parsing — the caller resolves flags into the explicit
// `WalletSyncCmdOptions` shape — and is dependency-injectable (fetch +
// stdout/stderr sinks) so it unit-tests in-process with no live vault.
//
// The whole-body push (mint-or-derive BEK -> wrap under AWK -> encrypt body ->
// PUT encrypted-blob-account) is assembled from the committed primitives
// (wrapBekUnderAwk / deriveAwkFromMaterial / bekFromAwk / encryptBodyBlob + the
// VaultClient account routes), mirroring the browser minter
// (tn_proto_web/static/account/project_minter.js steps 5-6) and the Python
// wallet_push.push_ceremony_body.

import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, extname, isAbsolute, join, resolve as pathResolve } from "node:path";

import { parse as parseYaml } from "yaml";

import { Identity, defaultIdentityPath } from "../identity.js";
import { NodeRuntime } from "../runtime/node_runtime.js";
import { VaultClient, vaultIdentityFromDeviceKey } from "../vault/client.js";
import { loadCachedAwk } from "../vault/awk_cache.js";
import { drainPendingAwk } from "../vault/awk_pickup.js";
import {
  bekFromAwk,
  deriveAwkFromMaterial,
  deriveBekFromMaterial,
  wrapBekUnderAwk,
  type CredentialWrap,
  type WrappedKeyRow,
} from "../vault/awk_bek.js";
import { encryptBodyBlob } from "../core/body_encryption.js";
import { bytesToB64 } from "../core/encoding.js";

/** Options for {@link walletSyncCmd}. Mirrors Python's `p_wallet_sync`
 *  parser: optional positional `yaml`; flags `--pull`, `--push-only`,
 *  `--drain-queue`. `passphrase` / `vault` / `identityPath` / `fetchImpl` /
 *  sinks are injected for the headless + test paths. */
export interface WalletSyncCmdOptions {
  /** Path to the ceremony `tn.yaml`. When omitted, discover via the
   *  standard chain (`$TN_YAML`, `./tn.yaml`, `~/.tn/tn.yaml`). */
  yaml?: string | undefined;
  /** `--pull`: stage the account inbox WITHOUT absorbing (back-compat). */
  pull?: boolean | undefined;
  /** `--push-only`: skip the pull/absorb step, push the body backup. */
  pushOnly?: boolean | undefined;
  /** `--drain-queue`: skip pull/absorb, retry the push (queue-drain). */
  drainQueue?: boolean | undefined;
  /** Account passphrase — derives the AWK to mint/derive the project BEK
   *  for the push. Required for the push leg UNLESS a cached `awk` is given. */
  passphrase?: string | undefined;
  /** Cached account AWK (the warm/init path — already unwrapped at connect
   *  time, see vault/credential_store.ts). Takes precedence over
   *  `passphrase`; lets the body backup run with no passphrase prompt. */
  awk?: Uint8Array | undefined;
  /** Vault URL override. Falls back to the ceremony's linked_vault, then
   *  the identity's cached linked_vault. */
  vault?: string | undefined;
  /** Override identity.json path (tests). Default: defaultIdentityPath(). */
  identityPath?: string | undefined;
  /** Override fetch (tests). Default: globalThis.fetch. */
  fetchImpl?: typeof fetch | undefined;
  /** Sink for normal output. Defaults to `process.stdout.write`. */
  stdout?: { write(s: string): void } | undefined;
  /** Sink for error output. Defaults to `process.stderr.write`. */
  stderr?: { write(s: string): void } | undefined;
}

/** Print `tn: error: <msg>` and return `code` — the value-returning TS
 *  analogue of Python's `_die` so the caller owns process exit. */
function die(err: { write(s: string): void }, msg: string, code = 1): number {
  err.write(`tn: error: ${msg}\n`);
  return code;
}

/** Resolve the yaml path: explicit arg (must exist) else the discovery
 *  chain (`$TN_YAML`, `./tn.yaml`, `~/.tn/tn.yaml`). Mirrors the branches
 *  of `_resolve_yaml_or_discover` the verb can reach. */
function resolveYamlOrDiscover(
  arg: string | undefined,
  err: { write(s: string): void },
): { yamlPath: string } | { code: number } {
  if (arg) {
    const p = pathResolve(arg);
    if (!existsSync(p)) return { code: die(err, `yaml not found: ${p}`) };
    return { yamlPath: p };
  }
  const env = process.env["TN_YAML"];
  if (env && existsSync(env)) {
    return { yamlPath: isAbsolute(env) ? env : pathResolve(env) };
  }
  const cwdYaml = pathResolve("tn.yaml");
  if (existsSync(cwdYaml)) return { yamlPath: cwdYaml };
  const homeYaml = pathResolve(homedir(), ".tn", "tn.yaml");
  if (existsSync(homeYaml)) return { yamlPath: homeYaml };
  return { code: die(err, "no tn.yaml found (pass --yaml or set $TN_YAML)") };
}

/** Per-yaml-stem `.tn/<stem>/` dir. Mirror of conventions._stem_dir for a
 *  yaml file path (.yaml/.yml). */
function stemDir(yamlPath: string): string {
  const ext = extname(yamlPath);
  const stem = ext === ".yaml" || ext === ".yml" ? basename(yamlPath, ext) : "tn";
  return join(dirname(yamlPath), ".tn", stem);
}

/** Inbox root for staged snapshots — `<yaml_dir>/.tn/<stem>/inbox/`.
 *  Mirror of conventions.inbox_dir. */
function inboxDir(yamlPath: string): string {
  return join(stemDir(yamlPath), "inbox");
}

/** Link-state + ceremony fields read straight from the yaml's `ceremony:`
 *  block (the TS loadConfig doesn't surface linked_vault/linked_project_id,
 *  and config.ts is off-limits — so we read the raw doc). Mirrors the fields
 *  Python's LoadedConfig.is_linked / linked_vault / linked_project_id read. */
interface CeremonyLinkState {
  ceremonyId: string;
  mode: string;
  linkedVault: string | null;
  linkedProjectId: string | null;
  isLinked: boolean;
}

function readLinkState(yamlPath: string): CeremonyLinkState {
  const doc = parseYaml(readFileSync(yamlPath, "utf8")) as Record<string, unknown> | null;
  const ceremony = (doc?.["ceremony"] ?? {}) as Record<string, unknown>;
  const ceremonyId = String(ceremony["id"] ?? "");
  const mode = String(ceremony["mode"] ?? "local");
  const linkedVault = (ceremony["linked_vault"] as string | undefined) || null;
  const linkedProjectId = (ceremony["linked_project_id"] as string | undefined) || null;
  return {
    ceremonyId,
    mode,
    linkedVault,
    linkedProjectId,
    isLinked: mode === "linked" && Boolean(linkedVault),
  };
}

/** `<yaml_dir>/.tn/<stem>/sync/state.json` — the sync-state sidecar that
 *  holds `account_bound`. Mirror of sync_state.state_path. */
function syncStatePath(yamlPath: string): string {
  return join(stemDir(yamlPath), "sync", "state.json");
}

/** True iff `account_bound` was previously stamped True. Mirror of
 *  sync_state.is_account_bound (missing/corrupt file => False). */
function isAccountBound(yamlPath: string): boolean {
  const p = syncStatePath(yamlPath);
  if (!existsSync(p)) return false;
  try {
    const doc = JSON.parse(readFileSync(p, "utf8")) as Record<string, unknown>;
    return typeof doc["account_bound"] === "boolean" ? (doc["account_bound"] as boolean) : false;
  } catch {
    return false;
  }
}

/** Path-sanitize a DID / ceremony_id / ts segment. DIDs carry ':' (illegal
 *  in Windows path components) and a malicious server value must not escape
 *  the inbox root. Mirror of cli._safe_path_seg — throws on '..' walks. */
function safePathSeg(seg: string): string {
  const cleaned = seg.replace(/:/g, "_").replace(/\//g, "_").replace(/\\/g, "_");
  if (cleaned === "" || cleaned === "." || cleaned === ".." || cleaned.startsWith("..")) {
    throw new Error(`unsafe path segment: ${JSON.stringify(seg)}`);
  }
  return cleaned;
}

/** Resolve the vault URL for a pull/push, preferring the CEREMONY's linked
 *  vault (where the push goes) over the identity default — otherwise the
 *  pull can connect-refuse against a fallback while the push succeeds.
 *  Mirrors `_stage_account_inbox`'s vault_url resolution. */
function resolveVaultUrl(
  link: CeremonyLinkState,
  identity: Identity,
  override: string | undefined,
): string | null {
  return override ?? link.linkedVault ?? identity.linkedVault ?? null;
}

/**
 * Pull the account-scoped inbox and STAGE new snapshots locally. Reuses the
 * dashboard's account aggregator (`GET /api/v1/account/inbox`) — every
 * snapshot addressed to any DID owned by this account. Each lands at
 * `<inbox_dir>/<from_did>/<ceremony_id>/<ts>.tnpkg`; already-staged files
 * are skipped (idempotent).
 *
 * Returns `{staged, skipped}`, or `null` when this ceremony can't pull (no
 * linked vault AND no account binding, or the vault doesn't resolve this DID
 * to an account — 401/403). Mirror of cli._stage_account_inbox.
 */
async function stageAccountInbox(
  link: CeremonyLinkState,
  identity: Identity,
  yamlPath: string,
  vaultOverride: string | undefined,
  fetchImpl: typeof fetch,
): Promise<{ staged: string[]; skipped: number } | null> {
  if (!link.isLinked && !isAccountBound(yamlPath)) return null;

  const vaultUrl = resolveVaultUrl(link, identity, vaultOverride);
  if (!vaultUrl) return null;

  const client = await VaultClient.forIdentity(
    vaultIdentityFromDeviceKey(identity.deviceKey()),
    vaultUrl,
    { fetchImpl },
  );

  // GET /api/v1/account/inbox — 401/403 means the vault doesn't resolve this
  // DID to an account; treat as "can't pull" (null), not an error.
  let listing: { items?: Record<string, unknown>[] };
  try {
    listing = await client.listAccountInbox();
  } catch (e) {
    const status = (e as { status?: number | null }).status ?? null;
    if (status === 401 || status === 403) return null;
    throw e;
  }

  const items = listing.items ?? [];
  const targetRoot = inboxDir(yamlPath);
  const staged: string[] = [];
  let skipped = 0;
  for (const item of items) {
    if (item["consumed_at"]) continue; // already absorbed elsewhere
    const fromDid = item["publisher_identity"];
    const ceremonyId = item["ceremony_id"];
    const ts = item["ts"];
    if (typeof fromDid !== "string" || typeof ceremonyId !== "string" || typeof ts !== "string") {
      continue;
    }
    const destDir = join(targetRoot, safePathSeg(fromDid), safePathSeg(ceremonyId));
    const dest = join(destDir, `${safePathSeg(ts)}.tnpkg`);
    if (existsSync(dest)) {
      skipped += 1;
      continue;
    }
    const body = await client.downloadAccountInboxSnapshot(fromDid, ceremonyId, ts);
    mkdirSync(destDir, { recursive: true });
    writeFileSync(dest, body);
    staged.push(dest);
  }
  return { staged, skipped };
}

/**
 * Pull the account inbox, ABSORB each staged snapshot (the merge), and
 * surface any INFORMED leaf-reuse (equivocation) attempts. Returns the count
 * of informed equivocations (0 when none / not account-bound). Absorb is
 * idempotent (dedupe by row_hash); the absorb engine keeps revoked leaves
 * revoked regardless — a re-add the publisher KNEW was revoked is flagged.
 * Mirror of cli._pull_absorb_step.
 */
async function pullAbsorbStep(
  link: CeremonyLinkState,
  identity: Identity,
  yamlPath: string,
  vaultOverride: string | undefined,
  fetchImpl: typeof fetch,
  out: { write(s: string): void },
): Promise<number> {
  const result = await stageAccountInbox(link, identity, yamlPath, vaultOverride, fetchImpl);
  if (result === null) {
    out.write(
      "  (pull/merge skipped: ceremony not bound to a vault account; " +
        "run `tn account connect <code>` to enable two-way sync)\n",
    );
    return 0;
  }

  const { staged, skipped } = result;
  let absorbed = 0;
  const informed: Array<{ group: string; leafIndex: number; attemptedRowHash: string }> = [];

  // Each absorb is a fresh, short-lived runtime over the SAME ceremony yaml
  // (mirrors Python's `from .pkg import absorb as _absorb` per-file call).
  for (const path of staged) {
    let rt: NodeRuntime | null = null;
    try {
      rt = NodeRuntime.init(yamlPath);
      const receipt = rt.absorbPkg(path);
      absorbed += receipt.acceptedCount ?? 0;
      for (const c of receipt.conflicts ?? []) {
        // Only the leaf-reuse variant carries the informed/leaf/row_hash
        // fields; narrow the ChainConflict union before reading them.
        if (c.type === "leaf_reuse_attempt" && c.informed) {
          informed.push({
            group: c.group,
            leafIndex: c.leafIndex,
            attemptedRowHash: c.attemptedRowHash,
          });
        }
      }
    } catch (e) {
      // One bad file shouldn't abort the merge.
      out.write(`  WARN absorb failed for ${basename(path)}: ${(e as Error).message}\n`);
    } finally {
      rt?.close();
    }
  }

  out.write(
    `  pulled+absorbed ${staged.length} snapshot(s), ${absorbed} new event(s)` +
      (skipped ? `, ${skipped} already local` : "") +
      "\n",
  );
  if (informed.length > 0) {
    out.write(
      `  ALERT: ${informed.length} INFORMED leaf-reuse (equivocation) ` +
        "attempt(s) — a publisher re-added a leaf it knew was revoked:\n",
    );
    for (const c of informed) {
      const rh = (c.attemptedRowHash || "").slice(0, 16);
      out.write(`    group=${c.group} leaf=${c.leafIndex} attempted=${rh}...\n`);
    }
  }
  return informed.length;
}

/**
 * `tn wallet sync --pull`: stage the account inbox WITHOUT absorbing. The
 * operator inspects the staged files and runs `tn absorb <path>` separately.
 * Mirror of cli._cmd_wallet_sync_pull. Dies (exit 2) when not account-bound.
 */
async function walletSyncPull(
  link: CeremonyLinkState,
  identity: Identity,
  yamlPath: string,
  vaultOverride: string | undefined,
  fetchImpl: typeof fetch,
  out: { write(s: string): void },
  err: { write(s: string): void },
): Promise<number> {
  const result = await stageAccountInbox(link, identity, yamlPath, vaultOverride, fetchImpl);
  if (result === null) {
    return die(
      err,
      "no account binding for this ceremony. Run `tn account connect <code>` " +
        "first to bind this DID to a vault account.",
      2,
    );
  }
  const { staged, skipped } = result;
  for (const p of staged) out.write(`staged -> ${p}\n`);
  out.write(`Pulled ${staged.length} snapshot(s); run \`tn absorb <path>\` on each to materialize.\n`);
  if (skipped) out.write(`  (${skipped} already staged locally and skipped)\n`);
  return 0;
}

/** Collect the ceremony body members keyed `body/<name>` for the push:
 *  every regular keystore file (minus transient `*.lock` mutexes) plus the
 *  yaml at `body/tn.yaml`. Mirrors wallet._ceremony_files (sans the opt-in
 *  log files) and the body layout project_minter.js packs. */
function collectBodyMembers(keystorePath: string, yamlPath: string): Map<string, Uint8Array> {
  const body = new Map<string, Uint8Array>();
  if (existsSync(keystorePath)) {
    for (const name of readdirSync(keystorePath).sort()) {
      const full = join(keystorePath, name);
      if (!statSync(full).isFile()) continue;
      if (extname(name) === ".lock") continue;
      body.set(`body/keys/${name}`, new Uint8Array(readFileSync(full)));
    }
  }
  body.set("body/tn.yaml", new Uint8Array(readFileSync(yamlPath)));
  return body;
}

/**
 * Mint-or-derive the project BEK, then encrypt + PUT the ceremony body.
 *
 *   - GET wrapped-key. If present -> derive the existing BEK from the
 *     account passphrase (deriveBekFromMaterial). If 404 -> MINT: generate a
 *     fresh 32-byte BEK, derive the AWK from the passphrase + credential,
 *     wrap the BEK under the AWK (wrapBekUnderAwk), and PUT wrapped-key.
 *   - Encrypt the body STORED-zip under the BEK as a no-AAD `nonce||ct`
 *     frame (encryptBodyBlob) — the exact shape restore.ts reads back.
 *   - PUT the frame (base64) to encrypted-blob-account with If-Match: the
 *     current generation, or "*" for the first write.
 *
 * Returns the number of body files uploaded (the single body counts each
 * member it carries, mirroring Python's per-file `uploaded` list length).
 */
async function pushCeremonyBody(
  client: VaultClient,
  projectId: string,
  body: Map<string, Uint8Array>,
  passphrase: string | null,
  awk: Uint8Array | null,
  _fetchImpl: typeof fetch,
): Promise<string[]> {
  // 1. Derive or mint the BEK. The AWK comes one of two ways: a cached AWK
  //    (the warm/init path — already unwrapped at connect time) or derived
  //    here from the passphrase. A cached AWK takes precedence.
  let bek: Uint8Array;
  let wrappedKeyExists = false;
  let wrapped: WrappedKeyRow | null = null;
  try {
    wrapped = (await client.getWrappedKey(projectId)) as unknown as WrappedKeyRow;
    wrappedKeyExists = Boolean(wrapped && wrapped.wrapped_bek_b64);
  } catch (e) {
    const status = (e as { status?: number | null }).status ?? null;
    if (status !== 404) throw e;
  }

  // The credential wrap is only needed to derive the AWK from a passphrase.
  const cred = awk ? null : ((await client.getCredentialWrap()) as unknown as CredentialWrap);
  if (wrappedKeyExists && wrapped) {
    bek = awk
      ? await bekFromAwk(awk, wrapped)
      : await deriveBekFromMaterial(passphrase as string, cred as CredentialWrap, wrapped);
  } else {
    // Mint a fresh BEK and register the project under the account by PUTting
    // the wrapped-key first (the encrypted-blob PUT checks ownership against
    // project_wrapped_keys — order matters, per project_minter.js step 5).
    bek = new Uint8Array(32);
    globalThis.crypto.getRandomValues(bek);
    const useAwk = awk ?? (await deriveAwkFromMaterial(passphrase as string, cred as CredentialWrap));
    const wrap = await wrapBekUnderAwk(useAwk, bek);
    await client.putWrappedKey(projectId, {
      wrapped_bek_b64: wrap.wrapped_bek_b64,
      wrap_nonce_b64: wrap.wrap_nonce_b64,
      cipher_suite: "aes-256-gcm",
    });
  }

  // 2. Encrypt the body as the no-AAD nonce||ct frame.
  const frame = await encryptBodyBlob(body, bek);

  // 3. If-Match generation from the existing blob (or "*" for first write).
  let ifMatch: string = "*";
  try {
    const blob = (await client.getEncryptedBlob(projectId)) as Record<string, unknown>;
    const gen = blob["generation"];
    if (typeof gen === "number" || (typeof gen === "string" && gen !== "")) {
      ifMatch = String(gen);
    }
  } catch (e) {
    const status = (e as { status?: number | null }).status ?? null;
    if (status !== 404) throw e;
    // 404 -> no blob yet -> first write -> If-Match: *
  }

  // 4. PUT the frame. ciphertext_b64 carries the WHOLE nonce||ct frame so it
  // round-trips through restore.ts::decryptBlobWithBek (which reads
  // ciphertext_b64 as the frame, no separate nonce). salt/kdf are
  // informational on the server (stored opaquely) — match project_minter.js.
  const salt = new Uint8Array(16);
  globalThis.crypto.getRandomValues(salt);
  await client.putEncryptedBlobAccount(
    projectId,
    {
      ciphertext_b64: bytesToB64(frame),
      // The server requires nonce_b64 alongside the frame (422 otherwise);
      // the no-AAD frame is nonce||ct, so the nonce is its first 12 bytes.
      // restore.ts reads ciphertext_b64 as the WHOLE frame, so this field is
      // informational for the server's envelope schema — it must still be
      // present. Mirrors wallet_sync_live.test.ts::pushBody.
      nonce_b64: bytesToB64(frame.subarray(0, 12)),
      salt_b64: bytesToB64(salt),
      kdf: "pbkdf2-sha256",
      kdf_params: { iterations: 1 },
      cipher_suite: "aes-256-gcm",
      bundle_kind: "project-body-v1",
    },
    { ifMatch },
  );

  // Mirror Python's per-file `uploaded` list: one entry per body member.
  return [...body.keys()].map((k) => k.replace(/^body\//, "")).sort();
}

/**
 * Publish the ceremony's group KEY material to the OWN account inbox so a
 * SECOND device on the same account ends up with the groups INSTALLED +
 * ROUTABLE after its next `pull -> absorb`. This is the merge-path companion
 * to the last-write-wins body push: the body blob is content (lost on
 * overwrite), the group keys ride the append-only inbox (union-merged).
 *
 * Exports a `group_keys` `.tnpkg` (group `.btn.state`/`.btn.mykit` + the yaml
 * `groups.<name>` blocks — NO device secret) and POSTs it to this device's
 * own inbox at `/api/v1/inbox/{did}/snapshots/{ceremony}/{ts}.tnpkg`.
 *
 * Best-effort: a ceremony with no btn groups (only `tn.agents`) publishes
 * nothing. Returns the published group names (empty when nothing was sent).
 */
async function publishGroupKeys(
  client: VaultClient,
  identity: Identity,
  yamlPath: string,
  ceremonyId: string,
): Promise<string[]> {
  const authorKey = identity.deviceKey();
  const ownDid = authorKey.did;
  const td = mkdtempSync(join(tmpdir(), "tn-groupkeys-"));
  const pkgPath = join(td, "group_keys.tnpkg");
  const rt = NodeRuntime.init(yamlPath);
  let names: string[];
  try {
    try {
      // Author the snapshot AS the account-bound identity DID — the vault's
      // inbox POST requires manifest.publisher_identity == auth_did.
      rt.exportGroupKeys(pkgPath, { signWith: authorKey, authorDid: ownDid });
    } catch {
      // No btn groups with key material — nothing to publish.
      return [];
    }
    names = listGroupNamesInYaml(yamlPath);
    const body = new Uint8Array(readFileSync(pkgPath));
    await client.postInboxSnapshot(ownDid, ceremonyId, `${inboxSnapshotTs()}.tnpkg`, body);
  } finally {
    rt.close();
    try {
      rmSync(td, { recursive: true, force: true });
    } catch {
      /* best-effort tempdir cleanup */
    }
  }
  return names;
}

/** Inbox snapshot timestamp `YYYYMMDDTHHMMSS<micros>Z` — the exact shape the
 *  vault's `_TS_RE` (`\d{8}T\d{6}\d{6}Z`) accepts. Mirrors Python's
 *  `datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")`. JS Date has only
 *  millisecond precision, so the micros are the ms padded to 6 digits. */
function inboxSnapshotTs(): string {
  const iso = new Date().toISOString(); // e.g. 2026-06-06T16:08:31.277Z
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z$/.exec(iso);
  if (!m) return iso.replace(/[-:.]/g, "").replace(/Z$/, "000Z");
  const [, y, mo, d, hh, mm, ss, ms] = m;
  return `${y}${mo}${d}T${hh}${mm}${ss}${ms}000Z`;
}

/** Group names declared in the ceremony's authoritative yaml (sans
 *  `tn.agents`). Used only for the push stdout line. */
function listGroupNamesInYaml(yamlPath: string): string[] {
  try {
    const doc = parseYaml(readFileSync(yamlPath, "utf8")) as Record<string, unknown> | null;
    const groups = (doc?.["groups"] ?? {}) as Record<string, unknown>;
    return Object.keys(groups).filter((g) => g !== "tn.agents").sort();
  } catch {
    return [];
  }
}

/**
 * Run the `tn wallet sync` verb. Returns the process exit code so a CLI
 * shell can `process.exit(await walletSyncCmd(...))`.
 *
 *   - `--pull`            stage only; exit 0, or die(2) when not bound.
 *   - bare / `--push-only` / `--drain-queue`: push the body backup; exit 0,
 *     or 1 on a missing-vault / push error; die(1) for the not-linked +
 *     push-only / not-bound cases.
 *
 * Mirror of cli.cmd_wallet_sync.
 */
export async function walletSyncCmd(opts: WalletSyncCmdOptions = {}): Promise<number> {
  const out = opts.stdout ?? process.stdout;
  const err = opts.stderr ?? process.stderr;
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);

  const resolved = resolveYamlOrDiscover(opts.yaml, err);
  if ("code" in resolved) return resolved.code;
  const yamlPath = resolved.yamlPath;

  const identityPath = opts.identityPath ?? defaultIdentityPath();
  const identity = Identity.load(identityPath);
  const link = readLinkState(yamlPath);

  // --pull is independent of the linked-vault push state: receive-side
  // parity. Stage the account inbox without absorbing.
  if (opts.pull) {
    return walletSyncPull(link, identity, yamlPath, opts.vault, fetchImpl, out, err);
  }

  const pushOnly = Boolean(opts.pushOnly);
  const drainQueue = Boolean(opts.drainQueue);

  // Step 1 (two-way sync): pull + absorb before pushing, so a revocation
  // another device/publisher made is merged into local state first and an
  // informed re-add is surfaced. Skipped for --push-only and --drain-queue.
  if (!pushOnly && !drainQueue) {
    await pullAbsorbStep(link, identity, yamlPath, opts.vault, fetchImpl, out);
  }

  // Step 2: push (backup keystore + yaml to the linked vault).
  if (!link.isLinked) {
    if (pushOnly) {
      return die(err, `ceremony ${link.ceremonyId} is not linked; nothing to push`);
    }
    if (!isAccountBound(yamlPath)) {
      return die(
        err,
        `ceremony ${link.ceremonyId} is not linked and not account-bound; ` +
          "nothing to sync. Run `tn wallet link` and/or `tn account connect <code>`.",
      );
    }
    out.write(
      "  (push skipped: ceremony not linked to a vault; " +
        "run `tn wallet link` to enable backup)\n",
    );
    return 0;
  }
  if (!link.linkedVault) {
    return die(err, `ceremony ${link.ceremonyId} reports linked but linked_vault is empty`);
  }
  if (!link.linkedProjectId) {
    return die(err, `ceremony ${link.ceremonyId} claims linked but has no linked_project_id; relink to repair`);
  }
  // Inbox drain (non-blocking pull half of the AWK autocache flow): the
  // browser sealed an AWK pickup to this device DID at claim/approve time;
  // draining it caches the AWK so the push below can wrap the BEK without a
  // passphrase. Best-effort — never throws. Skipped when a passphrase was
  // supplied (that path derives its own AWK). Mirrors Python cmd_wallet_sync.
  if (!opts.passphrase) {
    const drainUrl = opts.vault ?? link.linkedVault ?? identity.linkedVault;
    if (drainUrl) {
      const learned = await drainPendingAwk({
        vaultBase: drainUrl,
        deviceSeed: identity.seed,
        fetchImpl,
      });
      const learnedAcct = learned[0];
      if (learnedAcct && !identity.linkedAccountId) {
        identity.linkedAccountId = learnedAcct;
        identity.save();
      }
    }
  }
  // Auto-load the cached AWK when no passphrase was supplied and the identity
  // carries a linked account ID — mirrors Python's `attach_or_sync` cached-AWK
  // read. A missing or unreadable cache is silently ignored; the guard below
  // will then error with the "run account connect --passphrase" hint.
  const awk =
    opts.awk ??
    (!opts.passphrase && identity.linkedAccountId
      ? loadCachedAwk(identity.linkedAccountId) ?? undefined
      : undefined);

  if (!opts.passphrase && !awk) {
    return die(
      err,
      "account credential required to push the body backup: a cached AWK " +
        "(run `tn account connect --passphrase`) or `--passphrase`.",
    );
  }

  const vaultUrl = opts.vault ?? link.linkedVault;
  const client = await VaultClient.forIdentity(
    vaultIdentityFromDeviceKey(identity.deviceKey()),
    vaultUrl,
    { fetchImpl },
  );

  const cfg = NodeRuntime.init(yamlPath);
  let keystorePath: string;
  try {
    keystorePath = cfg.config.keystorePath;
  } finally {
    cfg.close();
  }
  const body = collectBodyMembers(keystorePath, yamlPath);

  let uploaded: string[];
  try {
    uploaded = await pushCeremonyBody(
      client,
      link.linkedProjectId,
      body,
      opts.passphrase ?? null,
      awk ?? null,
      fetchImpl,
    );
  } catch (e) {
    return die(err, `push failed for ${link.ceremonyId}: ${(e as Error).message}`);
  }

  // Step 3 (two-device group sync): in ADDITION to the last-write-wins body
  // blob, publish the ceremony's group KEY material to the OWN account inbox.
  // The other device's pull -> absorb then INSTALLS + REGISTERS the groups
  // (union-merged, idempotent) — so a group A added becomes USABLE on B
  // without depending on the body blob (which is overwritten on B's next
  // push). Best-effort: a publish failure must not fail the body sync.
  let publishedGroups: string[] = [];
  if (!drainQueue) {
    try {
      publishedGroups = await publishGroupKeys(client, identity, yamlPath, link.ceremonyId);
    } catch (e) {
      out.write(`  WARN group-keys publish failed: ${(e as Error).message}\n`);
    }
  }

  if (drainQueue) {
    out.write(`Drained sync queue for ${link.ceremonyId}\n`);
    out.write(`  uploaded ${uploaded.length} files\n`);
    return 0;
  }
  out.write(`Synced ${link.ceremonyId} -> ${link.linkedVault}\n`);
  out.write(`  uploaded ${uploaded.length} files: ${JSON.stringify(uploaded)}\n`);
  if (publishedGroups.length > 0) {
    out.write(`  published group keys to own inbox: ${JSON.stringify(publishedGroups)}\n`);
  }
  return 0;
}

// ── walletWatchCmd ─────────────────────────────────────────────────────────

/** Options for {@link walletWatchCmd}. Extends WalletSyncCmdOptions with loop
 *  controls so tests can run a finite number of iterations instantly. */
export interface WalletWatchCmdOptions extends WalletSyncCmdOptions {
  /** Stop after this many iterations. Default: Infinity (run forever). */
  maxIterations?: number | undefined;
  /** Override sleep between iterations (tests). Default: real setTimeout. */
  sleepImpl?: (ms: number) => Promise<void>;
  /** Override the sync function (tests). Default: walletSyncCmd itself. */
  syncImpl?: (opts: WalletSyncCmdOptions) => Promise<number>;
}

/** Read `ceremony.sync_interval_seconds` from the ceremony yaml, or 600. */
function readSyncInterval(yamlPath: string): number {
  try {
    const doc = parseYaml(readFileSync(yamlPath, "utf8")) as Record<string, unknown> | null;
    const ceremony = (doc?.["ceremony"] ?? {}) as Record<string, unknown>;
    const v = ceremony["sync_interval_seconds"];
    if (typeof v === "number" && Number.isFinite(v) && v > 0) return v;
  } catch {
    // Best-effort; fall through to default.
  }
  return 600;
}

/**
 * `tn wallet watch` — loop calling `tn wallet sync` then sleeping
 * `ceremony.sync_interval_seconds` (default 600 s). Runs until SIGINT or
 * `maxIterations` (tests). Returns the last sync exit code.
 *
 * `syncImpl` and `sleepImpl` are injectable so tests can run N iterations
 * with no real network or timers.
 */
export async function walletWatchCmd(opts: WalletWatchCmdOptions = {}): Promise<number> {
  const maxIter = opts.maxIterations ?? Infinity;
  const sleep =
    opts.sleepImpl ??
    ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const sync = opts.syncImpl ?? walletSyncCmd;

  // Strip the watch-only options before forwarding to the sync function.
  const syncOpts: WalletSyncCmdOptions = {
    yaml: opts.yaml,
    pull: opts.pull,
    pushOnly: opts.pushOnly,
    drainQueue: opts.drainQueue,
    passphrase: opts.passphrase,
    awk: opts.awk,
    vault: opts.vault,
    identityPath: opts.identityPath,
    fetchImpl: opts.fetchImpl,
    stdout: opts.stdout,
    stderr: opts.stderr,
  };

  let lastCode = 0;
  for (let i = 0; i < maxIter; i++) {
    lastCode = await sync(syncOpts);

    if (i + 1 < maxIter) {
      // Read interval after each sync so a yaml edit takes effect on the next
      // cycle.  When the yaml can't be resolved we fall back to the default.
      let intervalSec = 600;
      if (opts.yaml) {
        intervalSec = readSyncInterval(opts.yaml);
      } else {
        // Discover the yaml the same way walletSyncCmd does (env / cwd / home).
        const errSink = { write: (_s: string) => {} };
        const resolved = resolveYamlOrDiscover(undefined, errSink);
        if (!("code" in resolved)) {
          intervalSec = readSyncInterval(resolved.yamlPath);
        }
      }
      await sleep(intervalSec * 1000);
    }
  }
  return lastCode;
}
