// Polymorphic recipient input for tn.admin.addRecipient / revokeRecipient.
// Mirrors the Python `_resolve_recipient` helper in python/tn/admin/__init__.py.
//
// Three shapes:
//   - Plain DID string                             (resolves to recipientDid)
//   - Non-negative integer                         (resolves to leafIndex, btn only)
//   - 32-byte Uint8Array                           (resolves to publicKey, jwe only)
//   - Object with recipientDid / leafIndex /
//     publicKey / did / x25519PubB64 fields        (AddRecipientResult-like,
//                                                   contacts.yaml-like)
//
// Branded helper functions (did(), leafIndex(), publicKeyBytes()) provide
// compile-time narrowing for callers who want it; the resolver also accepts
// the raw underlying types so casual call sites stay terse.

declare const __did: unique symbol;
declare const __leaf: unique symbol;
declare const __pubkey: unique symbol;

export type Did = string & { readonly [__did]: never };
export type LeafIndex = number & { readonly [__leaf]: never };
export type PublicKeyBytes = Uint8Array & { readonly [__pubkey]: never };

export function did(s: string): Did {
  if (typeof s !== "string" || !s.startsWith("did:")) {
    throw new Error(`tn.admin: expected DID string (starts with 'did:'), got ${JSON.stringify(s)}`);
  }
  return s as Did;
}

export function leafIndex(n: number): LeafIndex {
  if (!Number.isInteger(n) || n < 0) {
    throw new Error(`tn.admin: leafIndex must be a non-negative integer, got ${n}`);
  }
  return n as LeafIndex;
}

export function publicKeyBytes(bytes: Uint8Array): PublicKeyBytes {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error(
      `tn.admin: public key must be a 32-byte Uint8Array, got length=${bytes?.length}`,
    );
  }
  return bytes as PublicKeyBytes;
}

/**
 * Object input — anything with one or more canonical fields, plus the
 * contacts.yaml row aliases (did / x25519PubB64). Returned by
 * `tn.admin.addRecipient` (AddRecipientResult) and `tn.admin.recipients()`.
 */
export interface RecipientLike {
  recipientDid?: string | null;
  leafIndex?: number | null;
  publicKey?: Uint8Array | null;
  // contacts.yaml row aliases
  did?: string | null;
  x25519PubB64?: string | null;
}

export type RecipientInput =
  | string
  | number
  | Uint8Array
  | RecipientLike;

export interface ResolvedRecipient {
  recipientDid: string | null;
  leafIndex: number | null;
  publicKey: Uint8Array | null;
}

function b64ToBytes(b64: string): Uint8Array {
  // Node + bun both expose Buffer; browser env falls through to atob.
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(b64, "base64"));
  }
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function resolveRecipient(value: RecipientInput): ResolvedRecipient {
  const out: ResolvedRecipient = { recipientDid: null, leafIndex: null, publicKey: null };
  if (typeof value === "boolean") {
    throw new TypeError("tn.admin: recipient cannot be a boolean (use a number for leafIndex)");
  }
  if (typeof value === "string") {
    if (!value.startsWith("did:")) {
      throw new Error(`tn.admin: recipient string must be a DID, got ${JSON.stringify(value)}`);
    }
    out.recipientDid = value;
    return out;
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error(`tn.admin: recipient number must be a non-negative integer leafIndex, got ${value}`);
    }
    out.leafIndex = value;
    return out;
  }
  if (value instanceof Uint8Array) {
    if (value.length !== 32) {
      throw new Error(`tn.admin: raw recipient bytes must be a 32-byte X25519 public key, got length=${value.length}`);
    }
    out.publicKey = value;
    return out;
  }
  if (value && typeof value === "object") {
    const v = value as RecipientLike;
    out.recipientDid = v.recipientDid ?? v.did ?? null;
    out.leafIndex = v.leafIndex ?? null;
    if (v.publicKey instanceof Uint8Array) {
      out.publicKey = v.publicKey;
    } else if (typeof v.x25519PubB64 === "string") {
      out.publicKey = b64ToBytes(v.x25519PubB64);
    }
    if (out.recipientDid === null && out.leafIndex === null && out.publicKey === null) {
      throw new Error(
        "tn.admin: recipient object must contain at least one of " +
          "recipientDid/did, leafIndex, publicKey/x25519PubB64",
      );
    }
    return out;
  }
  throw new TypeError(`tn.admin: unsupported recipient type ${typeof value}`);
}
