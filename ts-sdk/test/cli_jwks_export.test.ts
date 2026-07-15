import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { strict as assert } from "node:assert";
import { test } from "node:test";

import { x25519 } from "@noble/curves/ed25519";

import { jwksCmd } from "../src/cli/jwks.js";
import {
  jwksDocumentFingerprint,
  jwksPublicKeyBytes,
  localDeviceJwks,
  parseTnJwks,
} from "../src/core/jwks.js";
import { DeviceKey } from "../src/core/signing.js";

function sink(): { text: () => string; writer: Pick<typeof process.stdout, "write"> } {
  let captured = "";
  return {
    text: () => captured,
    writer: {
      write(chunk: string | Uint8Array): boolean {
        captured += typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk);
        return true;
      },
    },
  };
}

function tempYaml(): { dir: string; yaml: string } {
  const dir = mkdtempSync(join(tmpdir(), "tn-cli-jwks-"));
  const yaml = join(dir, "tn.yaml");
  writeFileSync(yaml, "ceremony:\n  id: test\n\ndevice:\n  device_identity: did:key:zTest\n", "utf8");
  return { dir, yaml };
}

function testDevice(): DeviceKey {
  return DeviceKey.fromSeed(new Uint8Array(32).fill(7));
}

test("jwks cli export prints local public signing JWKS to stdout", async () => {
  const tmp = tempYaml();
  const out = sink();
  const err = sink();
  const expected = localDeviceJwks(testDevice(), {
    issuedAt: "2026-07-15T00:00:00.000Z",
  });

  try {
    const code = await jwksCmd(["node", "tn-js", "jwks", "export", "--yaml", tmp.yaml], {
      stdout: out.writer,
      stderr: err.writer,
      loadJwks(yamlPath) {
        assert.equal(yamlPath, tmp.yaml);
        return expected;
      },
    });

    assert.equal(code, 0);
    assert.equal(err.text(), "");
    const parsed = parseTnJwks(JSON.parse(out.text()) as unknown);
    assert.deepEqual(parsed, expected);
    assert.equal(parsed.keys[0]?.use, "sig");
    assert.equal(parsed.keys[0]?.crv, "Ed25519");
    assert.doesNotMatch(out.text(), /local\.private|seed|private/i);
  } finally {
    rmSync(tmp.dir, { recursive: true, force: true });
  }
});

test("jwks cli export writes an output file and emits a JSON receipt", async () => {
  const tmp = tempYaml();
  const out = sink();
  const expected = localDeviceJwks(testDevice(), {
    kid: "audit-signing-2026-07",
    issuer: "did:key:zAuditProject",
  });
  const writes: Array<{ path: string; text: string }> = [];
  const outPath = join(tmp.dir, "public-jwks.json");

  try {
    const code = await jwksCmd(
      [
        "node",
        "tn-js",
        "jwks",
        "export",
        "--yaml",
        tmp.yaml,
        "--out",
        outPath,
        "--kid",
        "audit-signing-2026-07",
        "--issuer",
        "did:key:zAuditProject",
        "--json",
      ],
      {
        stdout: out.writer,
        loadJwks(_yamlPath, opts) {
          assert.equal(opts.kid, "audit-signing-2026-07");
          assert.equal(opts.issuer, "did:key:zAuditProject");
          return expected;
        },
        writeText(path, text) {
          writes.push({ path, text });
        },
      },
    );

    assert.equal(code, 0);
    assert.equal(writes.length, 1);
    assert.equal(writes[0]?.path, outPath);
    assert.deepEqual(parseTnJwks(JSON.parse(writes[0]?.text ?? "") as unknown), expected);

    const receipt = JSON.parse(out.text()) as {
      ok: boolean;
      verb: string;
      issuer: string;
      jwks_fingerprint: string;
      keys: Array<{ kid: string; use: string; alg: string; fingerprint: string }>;
    };
    assert.equal(receipt.ok, true);
    assert.equal(receipt.verb, "jwks.export");
    assert.equal(receipt.issuer, "did:key:zAuditProject");
    assert.equal(receipt.jwks_fingerprint, jwksDocumentFingerprint(expected));
    assert.deepEqual(receipt.keys, [
      {
        kid: "audit-signing-2026-07",
        use: "sig",
        alg: "EdDSA",
        fingerprint: expected.keys[0]?.tn_fingerprint ?? "",
      },
    ]);
  } finally {
    rmSync(tmp.dir, { recursive: true, force: true });
  }
});

test("jwks cli export supports real keystore loading for a project", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-cli-jwks-real-"));
  const keys = join(dir, "keys");
  const yaml = join(dir, "tn.yaml");
  const seed = new Uint8Array(32).fill(9);
  const device = DeviceKey.fromSeed(seed);
  const indexMaster = new Uint8Array(32).fill(3);
  const out = sink();

  try {
    writeFileSync(
      yaml,
      [
        "ceremony:",
        "  id: real-load",
        "  mode: local",
        "device:",
        `  device_identity: ${device.did}`,
        "keystore:",
        "  path: ./keys",
        "logs:",
        "  path: ./tn.ndjson",
        "groups: {}",
        "",
      ].join("\n"),
      "utf8",
    );
    mkdirSync(keys, { recursive: true });
    writeFileSync(join(keys, "local.private"), seed);
    writeFileSync(join(keys, "local.public"), device.did, "utf8");
    writeFileSync(join(keys, "index_master.key"), indexMaster);

    const code = await jwksCmd(["node", "tn-js", "jwks", "export", "--yaml", yaml], {
      stdout: out.writer,
    });

    assert.equal(code, 0);
    const jwks = parseTnJwks(JSON.parse(out.text()) as unknown);
    assert.equal(jwks.issuer, device.did);
    assert.equal(jwks.keys[0]?.use, "sig");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("jwks cli export can include local JWE encryption public keys", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-cli-jwks-jwe-"));
  const keys = join(dir, "keys");
  const yaml = join(dir, "tn.yaml");
  const seed = new Uint8Array(32).fill(11);
  const device = DeviceKey.fromSeed(seed);
  const indexMaster = new Uint8Array(32).fill(5);
  const jwePrivate = new Uint8Array(32).fill(17);
  const jwePublic = x25519.getPublicKey(jwePrivate);
  const out = sink();

  try {
    writeFileSync(
      yaml,
      [
        "ceremony:",
        "  id: jwe-load",
        "  mode: local",
        "  cipher: jwe",
        "device:",
        `  device_identity: ${device.did}`,
        "keystore:",
        "  path: ./keys",
        "logs:",
        "  path: ./tn.ndjson",
        "groups:",
        "  default:",
        "    policy: private",
        "    cipher: jwe",
        "    recipients: []",
        "",
      ].join("\n"),
      "utf8",
    );
    mkdirSync(keys, { recursive: true });
    writeFileSync(join(keys, "local.private"), seed);
    writeFileSync(join(keys, "local.public"), device.did, "utf8");
    writeFileSync(join(keys, "index_master.key"), indexMaster);
    writeFileSync(join(keys, "default.jwe.mykey"), jwePrivate);

    const code = await jwksCmd(
      ["node", "tn-js", "jwks", "export", "--yaml", yaml, "--include-encryption", "--group", "default"],
      { stdout: out.writer },
    );

    assert.equal(code, 0);
    const jwks = parseTnJwks(JSON.parse(out.text()) as unknown);
    assert.equal(jwks.keys.length, 2);
    const enc = jwks.keys.find((key) => key.use === "enc");
    assert.ok(enc);
    assert.equal(enc.kid, "default-jwe-current");
    assert.equal(enc.crv, "X25519");
    assert.deepEqual(jwksPublicKeyBytes(enc), jwePublic);
    assert.doesNotMatch(out.text(), /local\.private|jwe\.mykey|private/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("jwks cli export rejects requested encryption groups without JWE keys", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tn-cli-jwks-missing-jwe-"));
  const keys = join(dir, "keys");
  const yaml = join(dir, "tn.yaml");
  const seed = new Uint8Array(32).fill(13);
  const device = DeviceKey.fromSeed(seed);

  try {
    writeFileSync(
      yaml,
      [
        "ceremony:",
        "  id: missing-jwe",
        "device:",
        `  device_identity: ${device.did}`,
        "keystore:",
        "  path: ./keys",
        "logs:",
        "  path: ./tn.ndjson",
        "groups: {}",
        "",
      ].join("\n"),
      "utf8",
    );
    mkdirSync(keys, { recursive: true });
    writeFileSync(join(keys, "local.private"), seed);
    writeFileSync(join(keys, "local.public"), device.did, "utf8");
    writeFileSync(join(keys, "index_master.key"), new Uint8Array(32).fill(6));

    await assert.rejects(
      () =>
        jwksCmd([
          "node",
          "tn-js",
          "jwks",
          "export",
          "--yaml",
          yaml,
          "--include-encryption",
          "--group",
          "default",
        ]),
      /group "default" has no active JWE encryption key/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("jwks cli export reports unknown arguments as usage errors", async () => {
  const out = sink();
  const err = sink();
  const code = await jwksCmd(["node", "tn-js", "jwks", "export", "--bogus"], {
    stdout: out.writer,
    stderr: err.writer,
  });

  assert.equal(code, 2);
  assert.equal(out.text(), "");
  assert.match(err.text(), /^tn-js: jwks export: unknown argument --bogus\n$/);
});
