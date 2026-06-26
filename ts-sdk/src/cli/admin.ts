// `tn admin <sub>` — low-level ceremony admin sub-dispatcher.
//
// Typed extraction of the inline `adminCmd` from the untyped CLI dispatcher
// `bin/tn-js.mjs`. Ported VERBATIM: stdout/stderr bytes and exit codes are
// byte-identical to the .mjs (a spawn test asserts on them). Types only — no
// restructuring, no reworded output, no logic changes.
//
//     tn admin add-recipient    --yaml <p> --group <g> --out <kit> [--recipient-did <did>]
//     tn admin revoke-recipient --yaml <p> --group <g> --leaf <i> [--recipient-did <did>]
//     tn admin revoked-count    --yaml <p> --group <g>
//     tn admin rotate           --yaml <p> [--group <g> | --groups a,b] [--out <dir|.tnpkg>]
//
// The function takes the FULL process argv so the original `argv[3]` /
// `argv.slice(4)` indexing is preserved verbatim. `stdout`/`exit`/`die` are
// re-expressed against `process.*` and a local `die` byte-identical to the
// .mjs one (writes `tn-js: <msg>\n` to stderr, exits 2). The caller wires
// this into the dispatcher's `case "admin":`.

import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve as pathResolve } from "node:path";

import { compileKitBundleToFile } from "../compile.js";
import { NodeRuntime } from "../runtime/node_runtime.js";

/** Mirror of the .mjs `die`: print `tn-js: <msg>` to stderr, exit 2. */
function die(msg: string): never {
  process.stderr.write(`tn-js: ${msg}\n`);
  process.exit(2);
}

export async function adminCmd(argv: string[]): Promise<number> {
  const sub = argv[3];
  const rest = argv.slice(4);
  const opts: {
    yaml: string | null;
    group: string;
    out: string | null;
    did: string | null;
    leaf: number | null;
    groups: string | null;
    groupSpecified: boolean;
  } = {
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
    if (rest[i] === "--yaml") opts.yaml = rest[++i] ?? null;
    else if (rest[i] === "--group") {
      opts.group = rest[++i] ?? opts.group;
      opts.groupSpecified = true;
    } else if (rest[i] === "--out") opts.out = rest[++i] ?? null;
    else if (rest[i] === "--recipient-did") opts.did = rest[++i] ?? null;
    else if (rest[i] === "--leaf") opts.leaf = Number.parseInt(rest[++i] ?? "", 10);
    else if (rest[i] === "--groups") {
      opts.groups = rest[++i] ?? null;
      opts.groupSpecified = true;
    }
  }
  if (!opts.yaml) die("admin: --yaml <path> is required");
  const rt = NodeRuntime.init(opts.yaml);

  switch (sub) {
    case "add-recipient": {
      if (!opts.out) die("admin add-recipient: --out <kit-path> is required");
      const leaf = rt.addRecipient(opts.group, opts.out, opts.did ?? undefined);
      process.stdout.write(
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
      process.stdout.write(JSON.stringify({ ok: true, group: opts.group, leaf_index: opts.leaf }) + "\n");
      break;
    }
    case "revoked-count": {
      const count = rt.revokedCount(opts.group);
      process.stdout.write(JSON.stringify({ ok: true, group: opts.group, count }) + "\n");
      break;
    }
    case "rotate": {
      // Resolve target groups. Unlike add-recipient/revoke-recipient
      // (which require an explicit --group), rotate defaults to "every
      // non-internal group in the ceremony" — the deploy-shaped flow.
      const cfg = rt.config;
      let targets: string[];
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
      const recipientGroups = new Map<string, string[]>();
      for (const g of targets) {
        for (const rec of rt.recipients(g)) {
          if (rec.revoked) continue;
          const did = rec.recipient_identity;
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
      const rotated: Array<{ group: string; generation: number }> = [];
      for (const g of targets) {
        const r = rt.rotateGroup(g);
        rotated.push({ group: g, generation: r.generation });
      }

      if (recipientGroups.size === 0) {
        process.stdout.write(
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
      let outDir: string;
      let singleFile: string | null = null;
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
      const artifacts: string[] = [];
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
            yamlPath: opts.yaml,
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

      process.stdout.write(
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
  return 0;
}
