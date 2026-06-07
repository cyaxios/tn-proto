// Characterization tests for AdminStateReducer._applyEnvelope (the CC-94
// per-event-type reducer in src/core/admin/state.ts). Written BEFORE the
// decompose-into-handlers refactor so the extracted handlers must preserve
// every branch's behavior. Drives the public AdminStateReducer.apply().
import { strict as assert } from "node:assert";
import { test } from "node:test";

import { AdminStateReducer } from "../src/core/admin/state.js";

let _n = 0;
function env(
  event_type: string,
  fields: Record<string, unknown> = {},
  opts: { did?: string; seq?: number; rh?: string; ts?: string } = {},
): Record<string, unknown> {
  _n += 1;
  return {
    row_hash: opts.rh ?? `rh${_n}`,
    device_identity: opts.did ?? "did:key:zPub",
    event_type,
    sequence: opts.seq ?? _n,
    timestamp: opts.ts ?? `2026-01-01T00:00:0${_n % 10}Z`,
    ...fields,
  };
}

test("ceremony.init sets ceremony state", () => {
  const r = new AdminStateReducer();
  r.apply(env("tn.ceremony.init", { ceremony_id: "cer1", cipher: "btn", created_at: "2026-01-01T00:00:00Z" }));
  assert.equal(r.state.ceremony?.ceremonyId, "cer1");
  assert.equal(r.state.ceremony?.cipher, "btn");
});

test("group.added pushes a group", () => {
  const r = new AdminStateReducer();
  r.apply(env("tn.group.added", { group: "payments", cipher: "btn", publisher_identity: "did:key:zPub", added_at: "t" }));
  assert.equal(r.state.groups.length, 1);
  assert.equal(r.state.groups[0]!.group, "payments");
  assert.equal(r.state.groups[0]!.publisherDid, "did:key:zPub");
});

test("recipient.added pushes an active recipient", () => {
  const r = new AdminStateReducer();
  r.apply(env("tn.recipient.added", { group: "g", leaf_index: 3, recipient_identity: "did:key:zR", kit_sha256: "abc" }));
  assert.equal(r.state.recipients.length, 1);
  const rec = r.state.recipients[0]!;
  assert.equal(rec.group, "g");
  assert.equal(rec.leafIndex, 3);
  assert.equal(rec.recipientDid, "did:key:zR");
  assert.equal(rec.activeStatus, "active");
});

test("recipient.added with non-string group / non-number leaf is ignored", () => {
  const r = new AdminStateReducer();
  r.apply(env("tn.recipient.added", { group: 5, leaf_index: "x" }));
  assert.equal(r.state.recipients.length, 0);
});

test("recipient.added on a previously-revoked leaf -> leaf_reuse_attempt conflict, no add", () => {
  const r = new AdminStateReducer();
  r.apply(env("tn.recipient.added", { group: "g", leaf_index: 1, recipient_identity: "did:key:zR1" }));
  r.apply(env("tn.recipient.revoked", { group: "g", leaf_index: 1 }));
  r.apply(env("tn.recipient.added", { group: "g", leaf_index: 1, recipient_identity: "did:key:zR2" }));
  const c = r.conflicts.find((x) => x.type === "leaf_reuse_attempt");
  assert.ok(c, "expected a leaf_reuse_attempt conflict");
  // still only the original recipient (now revoked); the reuse was rejected
  assert.equal(r.state.recipients.length, 1);
});

test("recipient.added double-add on an already-active leaf -> leaf_reuse_attempt, first wins", () => {
  const r = new AdminStateReducer();
  r.apply(env("tn.recipient.added", { group: "g", leaf_index: 2, recipient_identity: "did:key:zA" }));
  r.apply(env("tn.recipient.added", { group: "g", leaf_index: 2, recipient_identity: "did:key:zB" }));
  assert.equal(r.state.recipients.length, 1);
  assert.equal(r.state.recipients[0]!.recipientDid, "did:key:zA");
  assert.ok(r.conflicts.some((c) => c.type === "leaf_reuse_attempt"));
});

test("recipient.revoked flips the active recipient to revoked + records revokedLeaves", () => {
  const r = new AdminStateReducer();
  r.apply(env("tn.recipient.added", { group: "g", leaf_index: 7, recipient_identity: "did:key:zR" }));
  r.apply(env("tn.recipient.revoked", { group: "g", leaf_index: 7 }, { rh: "revRH" }));
  assert.equal(r.state.recipients[0]!.activeStatus, "revoked");
  assert.ok([...r.revokedLeaves.values()].includes("revRH"));
});

test("rotation.completed pushes a rotation AND retires active recipients in the group", () => {
  const r = new AdminStateReducer();
  r.apply(env("tn.recipient.added", { group: "g", leaf_index: 1, recipient_identity: "did:key:zR" }));
  r.apply(env("tn.rotation.completed", { group: "g", generation: 2, previous_kit_sha256: "kitA", cipher: "btn" }));
  assert.equal(r.state.rotations.length, 1);
  assert.equal(r.state.rotations[0]!.generation, 2);
  assert.equal(r.state.recipients[0]!.activeStatus, "retired");
});

test("rotation.completed with a conflicting previous_kit at same (group,gen) -> rotation_conflict", () => {
  const r = new AdminStateReducer();
  r.apply(env("tn.rotation.completed", { group: "g", generation: 1, previous_kit_sha256: "kitA" }));
  r.apply(env("tn.rotation.completed", { group: "g", generation: 1, previous_kit_sha256: "kitB" }));
  const c = r.conflicts.find((x) => x.type === "rotation_conflict");
  assert.ok(c, "expected rotation_conflict");
});

test("coupon.issued pushes a coupon", () => {
  const r = new AdminStateReducer();
  r.apply(env("tn.coupon.issued", { group: "g", slot: 4, recipient_identity: "did:key:zR", issued_to: "alice" }));
  assert.equal(r.state.coupons.length, 1);
  assert.equal(r.state.coupons[0]!.slot, 4);
  assert.equal(r.state.coupons[0]!.issuedTo, "alice");
});

test("enrolment.compiled then absorbed updates the same enrolment to absorbed", () => {
  const r = new AdminStateReducer();
  r.apply(env("tn.enrolment.compiled", { group: "g", peer_identity: "did:key:zP", package_sha256: "pkg" }));
  r.apply(env("tn.enrolment.absorbed", { group: "g", publisher_identity: "did:key:zP", absorbed_at: "t2" }));
  assert.equal(r.state.enrolments.length, 1);
  assert.equal(r.state.enrolments[0]!.status, "absorbed");
});

test("enrolment.absorbed with no prior compiled pushes an absorbed enrolment", () => {
  const r = new AdminStateReducer();
  r.apply(env("tn.enrolment.absorbed", { group: "g", publisher_identity: "did:key:zP", package_sha256: "pkg" }));
  assert.equal(r.state.enrolments.length, 1);
  assert.equal(r.state.enrolments[0]!.status, "absorbed");
});

test("vault.linked then vault.unlinked links then stamps unlinkedAt", () => {
  const r = new AdminStateReducer();
  r.apply(env("tn.vault.linked", { vault_identity: "did:key:zV", project_id: "p1", linked_at: "t1" }));
  assert.equal(r.state.vaultLinks.length, 1);
  assert.equal(r.state.vaultLinks[0]!.vaultDid, "did:key:zV");
  r.apply(env("tn.vault.unlinked", { vault_identity: "did:key:zV", unlinked_at: "t2" }));
  assert.equal(r.state.vaultLinks[0]!.unlinkedAt, "t2");
});

test("duplicate row_hash is applied only once", () => {
  const r = new AdminStateReducer();
  const e = env("tn.recipient.added", { group: "g", leaf_index: 9, recipient_identity: "did:key:zR" }, { rh: "dupRH" });
  r.apply(e);
  r.apply(e);
  assert.equal(r.state.recipients.length, 1);
});

test("same (did,event_type,sequence) with different row_hash -> same_coordinate_fork conflict", () => {
  const r = new AdminStateReducer();
  r.apply(env("tn.group.added", { group: "g1" }, { did: "did:key:zX", seq: 5, rh: "rhA" }));
  r.apply(env("tn.group.added", { group: "g2" }, { did: "did:key:zX", seq: 5, rh: "rhB" }));
  const c = r.conflicts.find((x) => x.type === "same_coordinate_fork");
  assert.ok(c, "expected same_coordinate_fork");
});

test("envelope without a string row_hash is a no-op", () => {
  const r = new AdminStateReducer();
  r.apply({ event_type: "tn.group.added", group: "g" });
  assert.equal(r.state.groups.length, 0);
});
