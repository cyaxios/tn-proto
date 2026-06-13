// Single source of truth for the SDK's self-reported version + User-Agent.
//
// SDK_VERSION must match package.json's "version" — test/version_parity.test.ts
// enforces it, so a release bump that misses this file fails the run set.
// Kept as a literal (not a package.json read) so browser bundles and
// node paths share one import with no fs dependency.

export const SDK_VERSION = "0.6.0-beta.1";

/** User-Agent for every outbound HTTP call the SDK makes (vault, account,
 * wallet, bootstrap). Mirrors Python's dynamic `tn-proto/<version>`. */
export const USER_AGENT = `tn-proto-ts/${SDK_VERSION}`;
