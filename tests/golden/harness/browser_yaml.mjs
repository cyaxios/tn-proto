// Harness: drive the BROWSER producer (static/account/yaml_profile.js:buildTnYaml)
// in pure Node and print the yaml STRING to stdout.
//
// buildTnYaml is a pure string builder with no browser-only imports at module
// load (it does not touch Web Crypto, the DOM, or the registration flow — those
// live in project_minter.js). So we import it directly; no browser, no Playwright.
//
// Synthetic inputs stand in for what project_minter.js passes after it mints a
// device key in the browser: a device DID, a ceremony id, a project label.
// recipients are implicit (buildTnYaml self-addresses the device DID into every
// group, mirroring a fresh single-device ceremony).
//
// This surface is EXPECTED to be non-conformant on first run: buildTnYaml emits
// dead top-level `project_id:` and `label:` keys (yaml_profile.js:124-125).
//
// Usage: node browser_yaml.mjs            (prints yaml to stdout)
//   or:  node browser_yaml.mjs <out.yaml> (also writes the file there)

import { writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { join } from "node:path";

const WEB_REPO = "C:/codex/tn/tn_proto_web";
const modUrl = pathToFileURL(
  join(WEB_REPO, "static", "account", "yaml_profile.js"),
).href;
const { buildTnYaml } = await import(modUrl);

// Synthetic but realistic inputs. The DID is a valid-looking did:key; the test
// normalizes all DIDs to <DID> before shape comparison, so the exact value only
// matters for the loader leg (the test substitutes a real minted DID there).
const text = buildTnYaml({
  ceremonyId: "local_br0wser1",
  projectId: "01KSVEBROWSERPROJECTID0000",
  deviceDid: "did:key:z6GOLDENdevicexxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  label: "GoldenProj",
  profile: "transaction",
});

const outArg = process.argv[2];
if (outArg) writeFileSync(outArg, text, "utf-8");
process.stdout.write(text);
