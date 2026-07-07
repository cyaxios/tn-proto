// TS side of the jwe add_recipient cross-language proof.
// modes: pub <yaml> <keydir> <secret> | read <pubLog> <bKeystore> <secret>
// Run from the ts-sdk root: node --import tsx --import ./test/_setup_wasm.mjs test/cross_impl/jwe_proof.mts <mode> ...
import { readFileSync } from "node:fs";

const mode = process.argv[2];

if (mode === "pub") {
  const { NodeRuntime } = await import("../../src/runtime/node_runtime.js");
  const { AdminNamespace } = await import("../../src/admin/index.js");
  const [yaml, keydir, secret] = process.argv.slice(3);
  const rt = NodeRuntime.init(yaml!, { cipher: "jwe" });
  const bpub = new Uint8Array(readFileSync(`${keydir}/b_pub.bin`));
  await new AdminNamespace(rt).addRecipient("default", {
    recipientDid: "did:key:z6MkBproofjwe",
    publicKey: bpub,
  });
  await rt.emitAsync("info", "proof.rec", { secret, n: 42 });
} else if (mode === "read") {
  const { readAsRecipientAsync } = await import("../../src/read_as_recipient.js");
  const [pubLog, bKeystore, expect] = process.argv.slice(3);
  let ok = false;
  for await (const e of readAsRecipientAsync(pubLog!, bKeystore!, { group: "default" })) {
    const pt = (e.plaintext["default"] ?? {}) as Record<string, unknown>;
    if (pt["secret"] === expect && e.valid.signature) ok = true;
  }
  console.log("TS-READ", ok ? "OK" : "FAIL");
  process.exit(ok ? 0 : 1);
}
