import { test } from "node:test";
import { strict as assert } from "node:assert";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import { Tn } from "../src/tn.js";
import { readTnpkg } from "../src/tnpkg_io.js";
import { BODY_CIPHER_SUITE, BODY_FRAME, decryptBodyBlob } from "../src/core/body_encryption.js";

// Stage 2 interop: `tn.initUpload` must produce exactly the artefact the
// browser claim page (`static/claim/claim.js::decryptBody`) consumes —
// an outer tnpkg zip carrying `body/encrypted.bin` = `nonce || ct+tag`
// (AES-256-GCM, empty AAD), decryptable with the BEK delivered in the
// claim URL fragment (`#k=<base64url(bek)>`).
//
// This test captures the POSTed body via a mock fetch, recovers the BEK
// from the returned passwordB64, and round-trips the decrypt — the same
// sequence the browser runs.

test("initUpload produces a claim URL whose body decrypts with the fragment BEK", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    let capturedBody: Uint8Array | null = null;
    let capturedHeaders: Record<string, string> = {};
    let capturedUrl = "";

    const mockFetch = (async (url: string | URL, init?: RequestInit) => {
      capturedUrl = String(url);
      capturedHeaders = (init?.headers as Record<string, string>) ?? {};
      const b = init?.body as Uint8Array;
      capturedBody = new Uint8Array(b);
      return new Response(
        JSON.stringify({
          vault_id: "01TESTVAULTID0000000000000",
          expires_at: "2026-05-29T21:00:00Z",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as unknown as typeof fetch;

    const res = await tn.initUpload({ vaultBase: "http://localhost:38790/", fetchImpl: mockFetch });

    // 1. Wire shape.
    assert.equal(capturedUrl, "http://localhost:38790/api/v1/pending-claims");
    assert.equal(capturedHeaders["Content-Type"], "application/octet-stream");
    assert.ok(
      typeof capturedHeaders["X-Publisher-Did"] === "string" &&
        capturedHeaders["X-Publisher-Did"].startsWith("did:"),
      "X-Publisher-Did header should carry the device DID",
    );

    // 2. Claim URL shape: {base}/claim/{vault_id}#k={passwordB64}.
    assert.equal(res.claimUrl, `http://localhost:38790/claim/${res.vaultId}#k=${res.passwordB64}`);
    assert.equal(res.vaultId, "01TESTVAULTID0000000000000");

    // 3. Recover the BEK from the fragment and decrypt — the browser path.
    assert.ok(capturedBody, "POST body should have been captured");
    const bek = new Uint8Array(Buffer.from(res.passwordB64, "base64url"));
    assert.equal(bek.length, 32, "BEK must be 32 bytes");

    const { body } = readTnpkg(capturedBody!);
    assert.deepEqual([...body.keys()].sort(), ["body/encrypted.bin"]);
    const blob = body.get("body/encrypted.bin");
    assert.ok(blob, "tnpkg must carry body/encrypted.bin");

    const members = await decryptBodyBlob(blob!, bek);
    // The full_keystore body carries the private key + the yaml.
    const names = [...members.keys()];
    assert.ok(
      names.some((n) => n.endsWith("local.private")),
      `decrypted body should include local.private; saw ${JSON.stringify(names)}`,
    );
    assert.ok(
      names.some((n) => n.endsWith("tn.yaml")),
      `decrypted body should include tn.yaml; saw ${JSON.stringify(names)}`,
    );
  } finally {
    await tn.close();
  }
});

test("initUpload package manifest binds the single encrypted body member", async () => {
  const tn = await Tn.ephemeral({ stdout: false });
  try {
    let capturedBody: Uint8Array | null = null;
    const mockFetch = (async (_url: string | URL, init?: RequestInit) => {
      capturedBody = new Uint8Array(init?.body as Uint8Array);
      return new Response(
        JSON.stringify({
          vault_id: "01TESTVAULTID0000000000000",
          expires_at: "2026-05-29T21:00:00Z",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as unknown as typeof fetch;

    await tn.initUpload({ vaultBase: "http://localhost:38790/", fetchImpl: mockFetch });

    assert.ok(capturedBody, "POST body should have been captured");
    const { manifest, body } = readTnpkg(capturedBody!);
    assert.equal(manifest.kind, "full_keystore");
    assert.deepEqual([...body.keys()].sort(), ["body/encrypted.bin"]);

    const blob = body.get("body/encrypted.bin");
    assert.ok(blob, "tnpkg must carry body/encrypted.bin");
    const ciphertextSha256 =
      "sha256:" + createHash("sha256").update(Buffer.from(blob)).digest("hex");

    const bodyEncryption = manifest.state?.["body_encryption"] as Record<string, unknown>;
    assert.equal(bodyEncryption["cipher_suite"], BODY_CIPHER_SUITE);
    assert.equal(bodyEncryption["frame"], BODY_FRAME);
    assert.equal(bodyEncryption["nonce_bytes"], 12);
    assert.equal(bodyEncryption["ciphertext_sha256"], ciphertextSha256);
    assert.equal(bodyEncryption["recipient_wrap"], undefined);
    assert.equal(bodyEncryption["recipient_wraps"], undefined);
  } finally {
    await tn.close();
  }
});

test("initUpload sends X-Project-Name when the ceremony carries a project_name", async () => {
  // Mint a named root ceremony so ceremony.project_name is stamped, then
  // confirm initUpload forwards it as the X-Project-Name header.
  const { mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { ensureCeremonyOnDisk } = await import("../src/multi.js");
  const projectDir = mkdtempSync(join(tmpdir(), "tn-initupload-pn-"));
  // Mint an as-root project ceremony (stamps ceremony.project_name), the
  // same path `tn-js init <name>` takes.
  const yamlPath = ensureCeremonyOnDisk("acmeproj", { projectDir, asRoot: true });
  const tn = await Tn.init(yamlPath);
  try {
    let captured: Record<string, string> = {};
    const mockFetch = (async (_url: string | URL, init?: RequestInit) => {
      captured = (init?.headers as Record<string, string>) ?? {};
      return new Response(
        JSON.stringify({
          vault_id: "01TESTVAULTID0000000000000",
          expires_at: "2026-05-29T21:00:00Z",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as unknown as typeof fetch;

    await tn.initUpload({ vaultBase: "http://localhost:38790", fetchImpl: mockFetch });
    assert.equal(captured["X-Project-Name"], "acmeproj");
  } finally {
    await tn.close();
  }
});
