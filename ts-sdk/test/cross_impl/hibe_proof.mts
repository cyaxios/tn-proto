// TS side of the hibe grant_reader (add_recipient) cross-language proof.
//
// Secure flow (the grant kit is sealed to the reader's device key, so the reader
// must exist and share its real DID before the authority grants):
//   readerinit <readerYaml>                      -- reader: mint ceremony, print DID
//   auth   <yaml> <kitPath> <secret> <readerDid>  -- authority: grant reader, emit
//   absorb <readerYaml> <kitPath>                 -- reader: absorb (unseal) the kit
//   read   <authLog> <readerKeystore> <secret>
// Run from the ts-sdk root: node --import tsx --import ./test/_setup_wasm.mjs test/cross_impl/hibe_proof.mts <mode> ...
const mode = process.argv[2];

if (mode === "readerinit") {
  const { NodeRuntime } = await import("../../src/runtime/node_runtime.js");
  const [yaml] = process.argv.slice(3);
  const rt = NodeRuntime.init(yaml!); // reader's own btn default ceremony
  // rt.did is the only thing the harness reads from stdout.
  process.stdout.write(rt.did + "\n");
} else if (mode === "auth") {
  const { NodeRuntime } = await import("../../src/runtime/node_runtime.js");
  const { AdminNamespace } = await import("../../src/admin/index.js");
  const [yaml, kitPath, secret, readerDid] = process.argv.slice(3);
  const rt = NodeRuntime.init(yaml!, { cipher: "hibe" });
  await new AdminNamespace(rt).grantReader("default", {
    readerDid: readerDid!,
    outPath: kitPath,
  });
  rt.emit("info", "proof.rec", { secret, n: 42 }); // hibe emit is sync (wasm primitive)
} else if (mode === "absorb") {
  const { NodeRuntime } = await import("../../src/runtime/node_runtime.js");
  const [yaml, kitPath] = process.argv.slice(3);
  const rt = NodeRuntime.init(yaml!); // attach to the reader ceremony from readerinit
  await rt.absorbPkgAsync(kitPath!); // async: unseals a recipient-sealed kit
} else if (mode === "read") {
  const { readAsRecipientAsync } = await import("../../src/read_as_recipient.js");
  const [authLog, keystore, expect] = process.argv.slice(3);
  let ok = false;
  for await (const e of readAsRecipientAsync(authLog!, keystore!, { group: "default" })) {
    const pt = (e.plaintext["default"] ?? {}) as Record<string, unknown>;
    if (pt["secret"] === expect && e.valid.signature) ok = true;
  }
  console.log("TS-READ", ok ? "OK" : "FAIL");
  process.exit(ok ? 0 : 1);
}
