/**
 * SILO: C5 — Local groups + recipients in-process
 * TEST: Python publisher Alice mints kit + writes events; TS recipient Frank
 *       (browser shape) decrypts them.
 *
 * This is the load-bearing cross-language case: a Python service (cron
 * job, server, ingestion pipeline) writes encrypted-to-group logs that
 * a browser client (TS, same wasm crypto) must decrypt. If this is
 * green, the browser story is real; if it breaks, every Python →
 * browser handoff is theoretical.
 *
 * Flow:
 *   1. Spawn Python child:
 *        - hermetic identity dir, TN_NO_LINK=1
 *        - chdir tmpdir
 *        - tn.init()  (no link)
 *        - alice.admin.add_recipient("default", recipient_did=FRANK_DID,
 *            out_path=<bundle_dir>/default.btn.mykit)
 *        - tn.pkg.export(frank.tnpkg, kind="kit_bundle",
 *            cfg=alice.cfg, keystore=<bundle_dir>,
 *            to_did=FRANK_DID, groups=["default"])
 *        - tn.info("c5.crosslang.payment", amount=N) ×2
 *        - print JSON: { alice_log, frank_tnpkg, alice_did }
 *   2. TS Frank-side:
 *        - separate tmpdir, Tn.use("default")
 *        - frank.pkg.absorb(frankTnpkg)
 *        - frank.read({ log: aliceLog, asRecipient: frankKeystore,
 *            group: "default" })
 *        - assert both payments decrypt + fields intact
 *
 * Asserts (named):
 *   - "python-alice-printed-valid-payload"
 *   - "ts-frank-absorbed-kit"
 *   - "ts-frank-decrypted-python-events"
 *   - "ts-frank-fields-round-tripped-from-python"
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Tn } from "../../../ts-sdk/src/index.ts";
import { assertNamed, setTestContext } from "../../_shared/assertions.js";

const FRANK_DID = "did:key:zFrank0123456789abcdefghjkmnpqrstuvwx";

function pythonMintAndPublish(aliceDir: string): {
  alice_log: string;
  frank_tnpkg: string;
  alice_did: string;
} {
  const py = String.raw`
import json, os, sys
# Hermetic redirect — Python doesn't touch the developer's real user-home.
os.environ['TN_IDENTITY_DIR'] = r'${aliceDir.replace(/\\/g, "\\\\")}_id'
os.environ['TN_NO_LINK'] = '1'
os.chdir(r'${aliceDir.replace(/\\/g, "\\\\")}')

import tn
from pathlib import Path

tn.init()
cfg = tn.current_config()
alice_log = str(cfg.resolve_log_path())
alice_did = cfg.device.did

# Mint Frank's kit, bundle for transport. Use a workspace dir + the
# canonical .btn.mykit filename pattern.
bundle_dir = Path(r'${aliceDir.replace(/\\/g, "\\\\")}') / "alice_bundle_workspace"
bundle_dir.mkdir(parents=True, exist_ok=True)
kit_path = bundle_dir / "default.btn.mykit"
tn.admin.add_recipient("default", recipient_did=r'${FRANK_DID}', out_path=kit_path)

frank_tnpkg = bundle_dir / "frank.tnpkg"
tn.pkg.export(
    frank_tnpkg, kind="kit_bundle", cfg=cfg, keystore=bundle_dir,
    to_did=r'${FRANK_DID}', groups=["default"],
)

# Two payment envelopes, encrypted to default group.
tn.info("c5.crosslang.payment", amount=1000, currency="USD")
tn.info("c5.crosslang.payment", amount=250, currency="USD")
tn.flush_and_close()

print(json.dumps({
    "alice_log": alice_log,
    "frank_tnpkg": str(frank_tnpkg),
    "alice_did": alice_did,
}))
`;
  const pythonBin =
    process.env["TN_REGRESSION_PYTHON"] ??
    "C:/codex/tn/tn_proto/.venv/Scripts/python.exe";
  const proc = spawnSync(pythonBin, ["-c", py], {
    encoding: "utf-8",
    timeout: 30000,
  });
  if (proc.status !== 0) {
    throw new Error(
      `pythonMintAndPublish: python exited ${proc.status}. ` +
        `stderr=${proc.stderr?.slice(0, 600)}`,
    );
  }
  const last = proc.stdout.trim().split(/\r?\n/).pop() ?? "";
  return JSON.parse(last) as {
    alice_log: string;
    frank_tnpkg: string;
    alice_did: string;
  };
}

test("C5 (cross-lang): Python publisher, TS Frank decrypts", async () => {
  setTestContext({
    silo: "c5",
    test: "c5_ts_cross_language_python_publisher::py_to_ts",
  });

  const aliceDir = mkdtempSync(join(tmpdir(), "c5-py-alice-"));
  const a = pythonMintAndPublish(aliceDir);

  assertNamed({
    name: "python-alice-printed-valid-payload",
    expected: true,
    observed:
      typeof a.alice_did === "string" &&
      a.alice_did.startsWith("did:key:") &&
      typeof a.alice_log === "string" &&
      existsSync(a.alice_log) &&
      typeof a.frank_tnpkg === "string" &&
      existsSync(a.frank_tnpkg),
    onMiss: `Python's payload looked malformed: ${JSON.stringify(a)}`,
  });

  // TS Frank reads.
  const frankDir = mkdtempSync(join(tmpdir(), "c5-ts-frank-"));
  const cwdBefore = process.cwd();
  process.chdir(frankDir);

  let frank: Tn | undefined;
  try {
    frank = await Tn.use("default");
    const frankKeystore = (frank.config() as { keystorePath: string }).keystorePath;

    const receipt = await frank.pkg.absorb(a.frank_tnpkg);
    assertNamed({
      name: "ts-frank-absorbed-kit",
      expected: "kit_bundle",
      observed: receipt.kind,
      onMiss:
        `TS frank.pkg.absorb returned kind=${JSON.stringify(receipt.kind)}; ` +
        "expected 'kit_bundle'. Cross-language tnpkg format may have drifted.",
    });

    const decrypted: Array<Record<string, unknown>> = [];
    for (const entry of frank.read({
      log: a.alice_log,
      asRecipient: frankKeystore,
      group: "default",
    })) {
      const e = entry as unknown as {
        event_type?: string;
        hidden_groups?: string[];
        fields?: Record<string, unknown>;
      };
      if (e.event_type === "c5.crosslang.payment") {
        const hidden = e.hidden_groups ?? [];
        if (!hidden.includes("default")) {
          decrypted.push(e.fields ?? {});
        }
      }
    }

    assertNamed({
      name: "ts-frank-decrypted-python-events",
      expected: 2,
      observed: decrypted.length,
      onMiss:
        `TS Frank decrypted ${decrypted.length} Python-written events; ` +
        "expected 2. If 0, the wasm-side BTN decrypt path can't unwrap " +
        "Python-encrypted envelopes — that's the cross-language gap. " +
        "Check crypto/tn-btn (Rust) and the ts-sdk wasm bindings.",
    });

    const amounts = decrypted.map((f) => f["amount"]);
    assertNamed({
      name: "ts-frank-fields-round-tripped-from-python",
      expected: true,
      observed: amounts.includes(1000) && amounts.includes(250),
      onMiss:
        `Decrypted amounts: ${JSON.stringify(amounts)}; expected to ` +
        "contain 1000 and 250. The canonical-encode round-trip differs " +
        "between Python and TS for numeric fields.",
    });

    void assert;
  } finally {
    if (frank !== undefined) await frank.close();
    process.chdir(cwdBefore);
  }
});
