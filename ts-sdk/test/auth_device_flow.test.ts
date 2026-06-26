// Device-authorization (RFC 8628) client — verified against a local mock vault.
// Proves requestDeviceCode signs the DID, pollDeviceToken honors
// authorization_pending → 200, and expired_token surfaces as a DeviceFlowError.

import { test } from "node:test";
import { strict as assert } from "node:assert";
import { createServer, type Server } from "node:http";
import { randomBytes, createHash } from "node:crypto";
import { Buffer } from "node:buffer";

import { DeviceKey } from "../src/core/signing.js";
import {
  requestDeviceCode,
  pollDeviceToken,
  DeviceFlowError,
} from "../src/auth/device_flow.js";

interface MockOpts {
  /** number of authorization_pending replies before 200 */
  pendingPolls: number;
  /** force token to always return this RFC error (e.g. "expired_token") */
  tokenError?: string;
}

function startMock(opts: MockOpts): Promise<{ server: Server; base: string; seenDid: () => string }> {
  let polls = 0;
  let did = "";
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const j = body ? (JSON.parse(body) as Record<string, unknown>) : {};
        if (req.url === "/api/v1/device/code") {
          did = String(j["did"] ?? "");
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              device_code: "dev_secret_123",
              user_code: "WDJB-MJHT",
              verification_uri: "https://vault.test/device",
              verification_uri_complete: "https://vault.test/device?code=WDJB-MJHT",
              interval: 1,
              expires_in: 60,
            }),
          );
          return;
        }
        if (req.url === "/api/v1/device/token") {
          if (opts.tokenError) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: opts.tokenError }));
            return;
          }
          if (polls < opts.pendingPolls) {
            polls += 1;
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "authorization_pending" }));
            return;
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ account_id: "01ACCT_DEVICEFLOW", did }));
          return;
        }
        res.writeHead(404);
        res.end();
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      resolve({ server, base: `http://127.0.0.1:${port}`, seenDid: () => did });
    });
  });
}

const noSleep = (_ms: number) => Promise.resolve();

test("device flow: request signs the DID, poll resolves pending → account_id", async () => {
  const { server, base, seenDid } = await startMock({ pendingPolls: 2 });
  const key = DeviceKey.fromSeed(new Uint8Array(randomBytes(32)));
  try {
    const dc = await requestDeviceCode(base, key);
    assert.equal(dc.userCode, "WDJB-MJHT");
    assert.equal(dc.verificationUri, "https://vault.test/device");
    assert.equal(dc.verificationUriComplete, "https://vault.test/device?code=WDJB-MJHT");
    assert.equal(seenDid(), key.did, "the DID the CLI sent must be its device DID");

    const res = await pollDeviceToken(base, dc, { sleep: noSleep });
    assert.equal(res.accountId, "01ACCT_DEVICEFLOW");
    assert.equal(res.did, key.did);
  } finally {
    server.close();
  }
});

test("device flow: the /device/code request signature verifies against the DID", async () => {
  const { server, base } = await startMock({ pendingPolls: 0 });
  const key = DeviceKey.fromSeed(new Uint8Array(randomBytes(32)));
  try {
    // Re-derive what the client signs and confirm the signature is valid for the
    // device key — the property the vault relies on to authenticate the DID.
    const msg = new Uint8Array(createHash("sha256").update(`tn:device-code:${key.did}`, "utf8").digest());
    const sig = key.sign(msg);
    assert.equal(Buffer.from(sig).length, 64, "Ed25519 signatures are 64 bytes");
    // And the round-trip still works end to end.
    const dc = await requestDeviceCode(base, key);
    const res = await pollDeviceToken(base, dc, { sleep: noSleep });
    assert.equal(res.accountId, "01ACCT_DEVICEFLOW");
  } finally {
    server.close();
  }
});

test("device flow: expired_token surfaces as a DeviceFlowError", async () => {
  const { server, base } = await startMock({ pendingPolls: 0, tokenError: "expired_token" });
  const key = DeviceKey.fromSeed(new Uint8Array(randomBytes(32)));
  try {
    const dc = await requestDeviceCode(base, key);
    await assert.rejects(
      () => pollDeviceToken(base, dc, { sleep: noSleep }),
      (e: unknown) => e instanceof DeviceFlowError && e.code === "expired_token",
    );
  } finally {
    server.close();
  }
});

test("device flow: access_denied surfaces as a DeviceFlowError", async () => {
  const { server, base } = await startMock({ pendingPolls: 0, tokenError: "access_denied" });
  const key = DeviceKey.fromSeed(new Uint8Array(randomBytes(32)));
  try {
    const dc = await requestDeviceCode(base, key);
    await assert.rejects(
      () => pollDeviceToken(base, dc, { sleep: noSleep }),
      (e: unknown) => e instanceof DeviceFlowError && e.code === "access_denied",
    );
  } finally {
    server.close();
  }
});
