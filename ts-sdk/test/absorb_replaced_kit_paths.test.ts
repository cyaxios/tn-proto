// FINDINGS #6 cross-binding parity — TS AbsorbReceipt.replacedKitPaths.
// When absorb overwrites an existing kit, the receipt must surface the
// displaced path so programmatic callers can react rather than rely on
// a printed warning.

import { strict as assert } from "node:assert";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, basename } from "node:path";
import { test } from "node:test";

import { TNClient } from "../src/index.js";

const PROFESSOR_DID = "did:key:z6MkBobReceiptParity";

test("AbsorbReceipt.replacedKitPaths populated on overwrite (FINDINGS #6)", () => {
  const root = mkdtempSync(join(tmpdir(), "tn-replaced-kit-"));
  const aliceDir = join(root, "alice");
  const bobDir = join(root, "bob");
  try {
    // Alice mints a bundle for Bob.
    const alice = TNClient.init(join(aliceDir, "alice.yaml"), { stdout: false });
    const bundle = join(aliceDir, "bob.tnpkg");
    alice.bundleForRecipient(PROFESSOR_DID, bundle);
    alice.close();

    // Bob inits — has his own default.btn.mykit. Capture original
    // bytes so we can verify the .previous.* sidecar got the right
    // content after absorb's rename.
    const bob = TNClient.init(join(bobDir, "bob.yaml"), { stdout: false });
    const bobKeystore = bob.config.keystorePath;
    const ownKitPath = join(bobKeystore, "default.btn.mykit");
    const originalBytes = readFileSync(ownKitPath);

    const receipt = bob.absorb(bundle);
    bob.close();

    const replaced = receipt.replacedKitPaths ?? [];
    assert.ok(
      replaced.length > 0,
      `expected replacedKitPaths populated, got receipt=${JSON.stringify(receipt)}`,
    );
    assert.ok(
      replaced.some((p) => basename(p) === "default.btn.mykit"),
      `replaced paths must include default.btn.mykit; got ${JSON.stringify(replaced)}`,
    );

    // Verify the original bytes survive on a `.previous.<ts>` sidecar
    // (the failure mode we're guarding against is silent loss).
    const sidecars = readdirSync(bobKeystore).filter(
      (f: string) => f.startsWith("default.btn.mykit.previous."),
    );
    assert.ok(sidecars.length > 0, `no .previous.* sidecar found in ${bobKeystore}`);
    const preserved = sidecars.some((f: string) =>
      Buffer.from(readFileSync(join(bobKeystore, f))).equals(Buffer.from(originalBytes)),
    );
    assert.ok(preserved, "displaced kit bytes not preserved in any sidecar");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
