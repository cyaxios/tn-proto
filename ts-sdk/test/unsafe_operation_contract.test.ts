import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  UNSAFE_OPERATIONS,
  UNSAFE_RELAXATIONS,
  canonicalUnsafeOperationPayload,
  normalizeUnsafeOperationNotice,
  type UnsafeOperationNotice,
} from "../src/core/unsafe_operation.js";

test("unsafe operation and relaxation values are frozen", () => {
  assert.deepEqual(UNSAFE_OPERATIONS, [
    "read",
    "watch",
    "jwe_add_recipient",
    "hibe_grant",
    "legacy_package_import",
  ]);
  assert.deepEqual(UNSAFE_RELAXATIONS, [
    "verification_disabled",
    "signature_not_required",
    "unauthenticated_allowed",
    "unknown_writer_allowed",
    "unverified_key_binding",
    "plaintext_bearer_delivery",
    "legacy_signer_mismatch",
  ]);
});

test("unsafe operation notices contain exactly five fields and normalized relaxations", () => {
  const notice = normalizeUnsafeOperationNotice({
    operation: "read",
    relaxations: ["verification_disabled", "signature_not_required", "verification_disabled"],
    subject_did: "did:key:z6MkExample",
    group: "default",
    artifact_digest: "sha256:fixture",
  } satisfies UnsafeOperationNotice);

  assert.deepEqual(notice, {
    artifact_digest: "sha256:fixture",
    group: "default",
    operation: "read",
    relaxations: ["signature_not_required", "verification_disabled"],
    subject_did: "did:key:z6MkExample",
  });
  assert.deepEqual(Object.keys(notice), [
    "artifact_digest",
    "group",
    "operation",
    "relaxations",
    "subject_did",
  ]);
});

test("unsafe operation payload serialization is canonical", () => {
  const notice = {
    operation: "read",
    relaxations: ["verification_disabled"],
    subject_did: null,
    group: null,
    artifact_digest: null,
  } satisfies UnsafeOperationNotice;

  assert.equal(
    canonicalUnsafeOperationPayload(notice),
    '{"artifact_digest":null,"group":null,"operation":"read","relaxations":["verification_disabled"],"subject_did":null}',
  );
});
