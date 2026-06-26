// Layer 2 fs wrapper around core/agents_policy.ts. Re-exports the Layer 1
// parser surface and adds `loadPolicyFile` which reads the markdown file
// from disk before parsing.
//
// See ./core/agents_policy.ts for the parser semantics and the .tn/config/
// agents.md file format.

import { existsSync, readFileSync } from "node:fs";

import { parsePolicyText, policyPathFor, POLICY_RELATIVE_PATH } from "./core/agents_policy.js";
import type { PolicyDocument } from "./core/agents_policy.js";

export {
  POLICY_RELATIVE_PATH,
  REQUIRED_FIELDS,
  parsePolicyText,
  policyPathFor,
} from "./core/agents_policy.js";
export type { PolicyDocument, PolicyTemplate } from "./core/agents_policy.js";

/** Read `<yamlDir>/.tn/config/agents.md` from disk and parse it. Returns
 * `null` if the file is absent. Throws if the file is present but
 * malformed. */
export function loadPolicyFile(yamlDir: string): PolicyDocument | null {
  const p = policyPathFor(yamlDir);
  if (!existsSync(p)) return null;
  const text = readFileSync(p, "utf8");
  return parsePolicyText(text, POLICY_RELATIVE_PATH);
}
