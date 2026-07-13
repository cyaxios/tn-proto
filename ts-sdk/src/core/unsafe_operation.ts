export const UNSAFE_OPERATIONS = [
  "read",
  "watch",
  "jwe_add_recipient",
  "hibe_grant",
  "legacy_package_import",
] as const;

export type UnsafeOperation = (typeof UNSAFE_OPERATIONS)[number];

export const UNSAFE_RELAXATIONS = [
  "verification_disabled",
  "signature_not_required",
  "unauthenticated_allowed",
  "unknown_writer_allowed",
  "unverified_key_binding",
  "plaintext_bearer_delivery",
  "legacy_signer_mismatch",
] as const;

export type UnsafeRelaxation = (typeof UNSAFE_RELAXATIONS)[number];

export interface UnsafeOperationNotice {
  readonly operation: UnsafeOperation;
  readonly relaxations: readonly UnsafeRelaxation[];
  readonly subject_did: string | null;
  readonly group: string | null;
  readonly artifact_digest: string | null;
}

export function normalizeUnsafeOperationNotice(
  notice: UnsafeOperationNotice,
): UnsafeOperationNotice {
  return {
    artifact_digest: notice.artifact_digest,
    group: notice.group,
    operation: notice.operation,
    relaxations: [...new Set(notice.relaxations)].sort(),
    subject_did: notice.subject_did,
  };
}

export function canonicalUnsafeOperationPayload(notice: UnsafeOperationNotice): string {
  return JSON.stringify(normalizeUnsafeOperationNotice(notice));
}
