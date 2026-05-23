// Vault URL resolution — TS port of python/tn/vault_client.py
// (`resolve_vault_url`) + python/tn/identity.py (`_resolve_did_endpoint`).
//
// Two distinct helpers because the two Python functions resolve
// different things: `resolve_vault_url` is "where do my own vault
// requests go" (caller arg > TN_VAULT_URL > default), while
// `resolve_did_endpoint` is "where does *this DID's* vault live"
// (did:key uses TN_VAULT_DEFAULT_BASE; did:web fetches the DID doc).
//
// Both env reads match Python's semantics byte-for-byte so dev-mode
// "point at localhost" configs (TN_VAULT_URL=http://localhost:8790 etc.)
// work across the SDK boundary.

/** Default vault URL when caller doesn't pass one and TN_VAULT_URL is
 *  unset. Mirrors `python/tn/vault_client.py::DEFAULT_VAULT_URL`. */
export const DEFAULT_VAULT_URL = "https://vault.tn-proto.org";

/** Env var name. Centralised here and in identity-DID resolution. */
export const ENV_VAULT_URL = "TN_VAULT_URL";

/** Env var name for the did:key default-vault hint. */
export const ENV_VAULT_DEFAULT_BASE = "TN_VAULT_DEFAULT_BASE";

/**
 * Resolve vault URL with the standard precedence: explicit arg >
 * `TN_VAULT_URL` env var > `DEFAULT_VAULT_URL`. Mirrors Python's
 * `vault_client.resolve_vault_url`.
 */
export function resolveVaultUrl(baseUrl?: string | null): string {
  if (baseUrl) return baseUrl;
  return process.env[ENV_VAULT_URL] ?? DEFAULT_VAULT_URL;
}

// In-process cache: did_str -> base URL string. Mirrors Python's
// `_did_endpoint_cache` — `did:web` document fetches happen at most
// once per process per DID.
const _didEndpointCache: Map<string, string> = new Map();

/**
 * Derive the HTTP base URL for a vault service from a DID string.
 *
 * Supported DID methods (matches python/tn/identity.py:_resolve_did_endpoint):
 *
 * - `did:key:z...`  -> `TN_VAULT_DEFAULT_BASE` env var, default
 *   `https://vault.tn-proto.org`. The key is self-describing — there's
 *   no document to fetch.
 *
 * - `did:web:<host>` or `did:web:<host>:<path:segments>` -> fetch
 *   `https://<host>/.well-known/did.json` once per process, look for
 *   a `service` entry with `type === "TnVaultEndpoint"`, use its
 *   `serviceEndpoint`. Falls back to `https://<host>` when no
 *   matching service is found OR when the fetch fails.
 *
 * Returns a string with NO trailing slash (rstrip-equivalent).
 * Throws on unsupported DID methods.
 *
 * Async because did:web requires an HTTP fetch. Callers in synchronous
 * code paths can wrap in a one-shot Promise + `await`.
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

/** Test-only: clear the did-endpoint cache. */
export function _resetDidEndpointCacheForTests(): void {
  _didEndpointCache.clear();
}

/** Env var name for the auto-link opt-out. */
export const ENV_NO_LINK = "TN_NO_LINK";

/**
 * Whether auto-link is disabled by env. Mirrors the
 * `TN_NO_LINK=1` check in python/tn/__init__.py:494.
 *
 * Currently consulted by no code in the TS SDK — the auto-link path
 * itself hasn't been ported (depends on the `Identity` class, which
 * is Python-only today). Helper sits here so a future auto-link impl
 * picks up the env-var gate as a one-line check rather than
 * re-discovering the convention. The explicit `tn.vault.link(...)`
 * verb is deliberately NOT gated by this — it's an explicit user
 * call, not an automatic action.
 */
export function isAutoLinkDisabled(): boolean {
  return (process.env[ENV_NO_LINK] ?? "").trim() === "1";
}
