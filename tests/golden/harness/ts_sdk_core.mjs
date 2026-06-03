// Harness: drive the ts-sdk CORE producer (runtime/node_runtime.ts:createFreshCeremony)
// from the BUILT dist, write a fresh-ceremony tn.yaml into a temp dir, and print
// the yaml STRING to stdout so the Python conformance test can capture it.
//
// This is the ts-sdk core surface (#2 in the spec §5 inventory). It is the SAME
// producer tn-js's `init` reaches, but here we call it directly with project_name
// "GoldenProj" rather than going through the CLI / vault-link path.
//
// Usage: node ts_sdk_core.mjs            (prints yaml to stdout)
//   or:  node ts_sdk_core.mjs <out.yaml> (also writes the file there)

import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFreshCeremony } from "../../../ts-sdk/dist/runtime/node_runtime.js";

const dir = mkdtempSync(join(tmpdir(), "tnconf_tssdk_"));
const yamlPath = join(dir, "tn.yaml");

createFreshCeremony(yamlPath, { projectName: "GoldenProj", profile: "transaction" });

const text = readFileSync(yamlPath, "utf-8");
const outArg = process.argv[2];
if (outArg) writeFileSync(outArg, text, "utf-8");
process.stdout.write(text);
