/**
 * Vault URL resolution helpers.
 *
 * Two helpers, two different questions:
 *
 * - {@link resolveVaultUrl} answers "where do *my own* vault requests
 *   go?" — explicit arg > `TN_VAULT_URL` env > default. Mirrors
 *   `python/tn/vault_client.py::resolve_vault_url`.
 *
 * - {@link resolveDidEndpoint} answers "where does *this DID's* vault
 *   live?" — `did:key:` uses `TN_VAULT_DEFAULT_BASE`; `did:web:` fetches
 *   the DID document. Mirrors `python/tn/identity.py::_resolve_did_endpoint`.
 *
 * Plus {@link isAutoLinkDisabled} — the `TN_NO_LINK` env-var predicate
 * that future auto-link code in TS will gate on.
 *
 * Both env-var reads match Python's semantics byte-for-byte so dev-mode
 * "point at localhost" configs work across the SDK boundary.
 *
 * @packageDocumentation
 */

/**
 * Default vault URL when no explicit argument and no `TN_VAULT_URL`
 * env var is set. Points at the hosted tn-proto vault.
 *
 * Mirrors `python/tn/vault_client.py::DEFAULT_VAULT_URL`.
 *
 * @public
 */
export const DEFAULT_VAULT_URL = "https://vault.tn-proto.org";

/**
 * Env var name for the primary vault URL. Read by
 * {@link resolveVaultUrl}.
 *
 * @public
 */
export const ENV_VAULT_URL = "TN_VAULT_URL";

/**
 * Env var name for the `did:key:` default-vault hint. Read by
 * {@link resolveDidEndpoint}.
 *
 * @public
 */
export const ENV_VAULT_DEFAULT_BASE = "TN_VAULT_DEFAULT_BASE";

/**
 * Resolve the vault base URL using the standard precedence:
 *
 * 1. Explicit `baseUrl` argument (when truthy).
 * 2. `TN_VAULT_URL` env var.
 * 3. {@link DEFAULT_VAULT_URL} (the hosted tn-proto vault).
 *
 * @param baseUrl - optional explicit base URL. `null` and `undefined`
 *   both fall through to the env var.
 *
 * @returns The resolved vault base URL. No trailing-slash normalisation
 *   is applied here; callers that build paths should
 *   `url.replace(/\/+$/, "")` defensively before appending.
 *
 * @example
 * ```ts
 * import { resolveVaultUrl } from "tn-proto";
 *
 * // No arg, no env: returns DEFAULT_VAULT_URL.
 * resolveVaultUrl();                        // "https://vault.tn-proto.org"
 *
 * // Env: TN_VAULT_URL=http://localhost:8790
 * resolveVaultUrl();                        // "http://localhost:8790"
 *
 * // Explicit arg wins over env.
 * resolveVaultUrl("https://other.example"); // "https://other.example"
 * ```
 *
 * @see {@link resolveDidEndpoint} - for "where does this DID's vault live?"
 * @see {@link ENV_VAULT_URL}
 * @see {@link DEFAULT_VAULT_URL}
 * @see [spec/vault-http](https://github.com/cyaxios/tn-proto/blob/main/docs/spec/vault-http.md) - the API rooted at this base URL.
 * @see [spec/env-vars#tn_vault_url](https://github.com/cyaxios/tn-proto/blob/main/docs/spec/env-vars.md) - precedence rules.
 *
 * @remarks
 * Mirrors `python/tn/vault_client.py::resolve_vault_url`. Pure function;
 * no I/O.
 *
 * @public
 */
export function resolveVaultUrl(baseUrl?: string | null): string {
  if (baseUrl) return baseUrl;
  return process.env[ENV_VAULT_URL] ?? DEFAULT_VAULT_URL;
}

/**
 * In-process cache: `did_str` -> base URL. Mirrors Python's
 * `_did_endpoint_cache`. `did:web:` document fetches happen at most
 * once per (process, DID).
 *
 * @internal
 */
const _didEndpointCache: Map<string, string> = new Map();

/**
 * Derive the HTTP base URL for a vault service from a DID string.
 *
 * Supported DID methods:
 *
 * - `did:key:z...` — the key is self-describing; no document to
 *   fetch. The transport URL comes from `TN_VAULT_DEFAULT_BASE`
 *   ({@link DEFAULT_VAULT_URL} when unset). Set the env var to
 *   `http://localhost:8790` to point at a local tn-proto-org instance
 *   for dev/tests.
 *
 * - `did:web:<host>` or `did:web:<host>:<path:segments>` — fetches
 *   `https://<host>/.well-known/did.json` once per process, looks for
 *   a `service` entry whose `type === "TnVaultEndpoint"`, and uses
 *   its `serviceEndpoint`. Falls back to `https://<host>` when no
 *   matching service entry is found OR when the fetch fails.
 *
 * Results are memoised per-DID for the lifetime of the process; the
 * first call for a given DID may incur a network round-trip
 * (`did:web:` only), every call thereafter is `O(1)` map lookup.
 *
 * @param didStr - the DID to resolve. Must be `did:key:` or `did:web:`.
 *
 * @returns The HTTP base URL with no trailing slash. Use as the prefix
 *   for vault API paths like `${base}/api/v1/auth/challenge`.
 *
 * @throws Error - when `didStr` uses an unsupported DID method. Empty
 *   strings, malformed prefixes, and `did:plc:`/`did:ion:`/etc all
 *   raise.
 *
 * @example
 * ```ts
 * import { resolveDidEndpoint } from "tn-proto";
 *
 * // did:key — uses TN_VAULT_DEFAULT_BASE (or DEFAULT_VAULT_URL).
 * const base1 = await resolveDidEndpoint("did:key:z6MkfakeDidKeyForTest");
 * // -> "https://vault.tn-proto.org"
 *
 * // did:web — fetches /.well-known/did.json from the host.
 * const base2 = await resolveDidEndpoint("did:web:vault.example.com");
 * // -> the TnVaultEndpoint serviceEndpoint, or "https://vault.example.com"
 * ```
 *
 * @see {@link resolveVaultUrl} - for explicit base URLs (not DID-derived).
 * @see {@link ENV_VAULT_DEFAULT_BASE}
 * @see [spec/signing#did-format](https://github.com/cyaxios/tn-proto/blob/main/docs/spec/signing.md#did-format) - DID method conventions.
 * @see [spec/vault-http](https://github.com/cyaxios/tn-proto/blob/main/docs/spec/vault-http.md) - what the returned URL roots.
 *
 * @remarks
 * Mirrors `python/tn/identity.py::_resolve_did_endpoint`. Trailing
 * slashes are stripped from the returned URL (consistent with Python's
 * `.rstrip("/")`).
 *
 * @public
 */
export async function resolveDidEndpoint(didStr: string): Promise<string> {
  const cached = _didEndpointCache.get(didStr);
  if (cached !== undefined) return cached;

  if (didStr.startsWith("did:key:")) {
    const base = (process.env[ENV_VAULT_DEFAULT_BASE] ?? DEFAULT_VAULT_URL).replace(/\/+$/, "");
    _didEndpointCache.set(didStr, base);
    return base;
  }

  if (didStr.startsWith("did:web:")) {
    // did:web:host  or  did:web:host:path:segments
    // per the did:web spec, colons after the host encode path separators.
    const parts = didStr.slice("did:web:".length).split(":");
    const host = parts[0] ?? "";
    const wellKnown = `https://${host}/.well-known/did.json`;

    try {
      // 5-second timeout matches python/tn/identity.py:427.
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), 5000);
      const resp = await fetch(wellKnown, { signal: ac.signal });
      clearTimeout(timer);
      if (resp.ok) {
        const doc = (await resp.json()) as { service?: Array<{ type?: string; serviceEndpoint?: string }> };
        if (Array.isArray(doc.service)) {
          for (const svc of doc.service) {
            if (svc.type === "TnVaultEndpoint" && typeof svc.serviceEndpoint === "string") {
              const endpoint = svc.serviceEndpoint.replace(/\/+$/, "");
              _didEndpointCache.set(didStr, endpoint);
              return endpoint;
            }
          }
        }
      }
    } catch (err) {
      console.warn(
        `_resolveDidEndpoint: could not fetch DID doc for ${didStr} ` +
          `(${(err as Error).message ?? String(err)}) -- falling back to https://${host}`,
      );
    }

    const fallback = `https://${host}`;
    _didEndpointCache.set(didStr, fallback);
    return fallback;
  }

  throw new Error(
    `resolveDidEndpoint: unsupported DID method in ${JSON.stringify(didStr)}. ` +
      `Supported: did:key, did:web`,
  );
}

/**
 * Clear the did-endpoint cache. Test-only; production code must not
 * call this.
 *
 * @example
 * ```ts
 * import { _resetDidEndpointCacheForTests, resolveDidEndpoint } from "tn-proto";
 *
 * afterEach(() => _resetDidEndpointCacheForTests());
 * ```
 *
 * @internal
 */
export function _resetDidEndpointCacheForTests(): void {
  _didEndpointCache.clear();
}

/**
 * Env var name for the auto-link opt-out. Read by
 * {@link isAutoLinkDisabled}.
 *
 * @public
 */
export const ENV_NO_LINK = "TN_NO_LINK";

/**
 * Whether the `TN_NO_LINK=1` env var is set, signalling that any
 * auto-link path should be skipped.
 *
 * Mirrors the gate at `python/tn/__init__.py:494`. Only the exact
 * string `"1"` is treated as enabled (after trim), matching Python.
 *
 * @returns `true` iff `TN_NO_LINK` is exactly `"1"`; `false` otherwise
 *   (including unset, empty, `"yes"`, `"true"`).
 *
 * @example
 * ```ts
 * import { isAutoLinkDisabled } from "tn-proto";
 *
 * // TN_NO_LINK=1 in env
 * isAutoLinkDisabled();   // true
 *
 * // TN_NO_LINK=yes in env (NOT "1", so Python ignores it; we do too)
 * isAutoLinkDisabled();   // false
 *
 * // TN_NO_LINK unset
 * isAutoLinkDisabled();   // false
 * ```
 *
 * @remarks
 * Consulted by no code in the TS SDK today — the auto-link path itself
 * hasn't been ported (depends on the `Identity` class, which is
 * Python-only). The helper sits ready so a future TS auto-link can
 * gate on the env var with a one-line check rather than re-discovering
 * the convention.
 *
 * **Explicitly NOT gated by this:** `tn.vault.link(...)` and
 * `tn.vault.unlink(...)`. Those are explicit user calls; surprising
 * them with a silent no-op based on env would be wrong.
 *
 * @see {@link ENV_NO_LINK}
 * @see [spec/env-vars#tn_no_link](https://github.com/cyaxios/tn-proto/blob/main/docs/spec/env-vars.md) - truthiness convention.
 * @public
 */
export function isAutoLinkDisabled(): boolean {
  return (process.env[ENV_NO_LINK] ?? "").trim() === "1";
}
