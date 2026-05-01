import {
  adminCatalogKinds as rawCatalogKinds,
  adminReduce as rawReduce,
  adminValidateEmit as rawValidateEmit,
} from "./raw.js";

export type StateDeltaKind =
  | "ceremony_init"
  | "group_added"
  | "recipient_added"
  | "recipient_revoked"
  | "coupon_issued"
  | "rotation_completed"
  | "enrolment_compiled"
  | "enrolment_absorbed"
  | "vault_linked"
  | "vault_unlinked"
  | "unknown";

export interface StateDelta {
  kind: StateDeltaKind;
  [key: string]: unknown;
}

export interface AdminEventKind {
  event_type: string;
  sign: boolean;
  sync: boolean;
  schema: Array<[string, string]>;
}

/** Reduce an envelope to a typed state delta. See Rust `StateDelta`. */
export function reduce(envelope: object): StateDelta {
  return rawReduce(envelope) as StateDelta;
}

/** List the catalogued admin event kinds. */
export function catalogKinds(): AdminEventKind[] {
  return rawCatalogKinds() as AdminEventKind[];
}

/** Throws if `fields` does not match the catalog schema for `eventType`. */
export function validateEmit(eventType: string, fields: object): void {
  rawValidateEmit(eventType, fields);
}
