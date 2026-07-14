import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { Entry } from "../src/Entry.js";
import { Tn } from "../src/tn.js";

function jweFrame(envelope: Record<string, unknown>): Record<string, unknown> {
  const group = envelope["default"] as Record<string, unknown>;
  return JSON.parse(Buffer.from(String(group["ciphertext"]), "base64").toString("utf8")) as Record<
    string,
    unknown
  >;
}

test("ordinary emit, read, seal, and unseal round-trip standard JWE", async () => {
  const root = mkdtempSync(join(tmpdir(), "tn-jwe-four-verbs-"));
  const tn = await Tn.init(join(root, "tn.yaml"), { cipher: "jwe", stdout: false });
  try {
    const receipt = tn.emit("info", "record.created", { secret: "from emit" });
    assert.ok(receipt.eventId);

    const entries = [...tn.read()]
      .filter((entry): entry is Entry => entry instanceof Entry)
      .filter((entry) => entry.event_type === "record.created");
    assert.equal(entries.length, 1);
    assert.equal(entries[0]!.fields["secret"], "from emit");

    const raw = [...tn.read({ raw: true })].find(
      (entry) => (entry as Record<string, unknown>)["event_type"] === "record.created",
    ) as Record<string, unknown>;
    const emittedJwe = jweFrame(raw);
    assert.ok(Array.isArray(emittedJwe["recipients"]));
    assert.equal(typeof emittedJwe["protected"], "string");
    assert.equal(typeof emittedJwe["ciphertext"], "string");

    const sealed = await tn.seal(
      "record.portable",
      { secret: "from seal" },
      { aad: { purpose: "round-trip" }, receipt: false },
    );
    assert.equal(typeof jweFrame(sealed.envelope)["aad"], "string");
    const opened = await tn.unseal(sealed);
    assert.ok(opened instanceof Entry);
    assert.equal(opened.fields["secret"], "from seal");
  } finally {
    await tn.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test("ordinary JWE emit fails closed when recipient material is unavailable", async () => {
  const root = mkdtempSync(join(tmpdir(), "tn-jwe-fail-closed-"));
  const tn = await Tn.init(join(root, "tn.yaml"), { cipher: "jwe", stdout: false });
  try {
    const config = tn.config() as { keystorePath: string; logPath: string };
    rmSync(join(config.keystorePath, "default.jwe.recipients"));
    assert.throws(
      () => tn.emit("info", "record.must-not-drop", { secret: "required" }),
      /recipients/,
    );
    const log = existsSync(config.logPath) ? readFileSync(config.logPath, "utf8") : "";
    assert.equal(log.includes("record.must-not-drop"), false);
  } finally {
    await tn.close();
    rmSync(root, { recursive: true, force: true });
  }
});
