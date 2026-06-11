// SDK error classes. Real Error subclasses so consumers can `try/catch` and
// route by `instanceof`. The matching data interfaces in admin_cache.ts /
// core/admin_state.ts stay separate — they're accumulator types for the
// state-reducer, not thrown values.
//
// Mirror in Python: tn.VerifyError, tn.admin.cache.ChainConflict /
// RotationConflict / LeafReuseAttempt / SameCoordinateFork. The Python
// names (without the `Error` suffix) follow Python idiom; the TS names
// carry `Error` suffixes per TS convention. docs/sdk-parity.md (Phase 4)
// documents the cross-language mapping.

export class VerificationError extends Error {
  readonly envelope: Record<string, unknown>;
  readonly invalidReasons: string[];
  constructor(envelope: Record<string, unknown>, invalidReasons: string[]) {
    const et = envelope["event_type"];
    const eid = envelope["event_id"];
    super(
      `secureRead: envelope event_type=${JSON.stringify(et)} ` +
        `event_id=${JSON.stringify(eid)} failed verification: ` +
        JSON.stringify(invalidReasons),
    );
    this.name = "VerificationError";
    this.envelope = envelope;
    this.invalidReasons = [...invalidReasons];
  }
}

export class ChainConflictError extends Error {
  readonly group: string;
  readonly localHead: string;
  readonly remoteHead: string;
  constructor(group: string, localHead: string, remoteHead: string) {
    super(
      `tn.admin chain conflict on group="${group}": ` +
      `local=${localHead.slice(0, 12)}… vs remote=${remoteHead.slice(0, 12)}…`,
    );
    this.name = "ChainConflictError";
    this.group = group;
    this.localHead = localHead;
    this.remoteHead = remoteHead;
  }
}

export class RotationConflictError extends Error {
  readonly group: string;
  readonly localGeneration: number;
  readonly remoteGeneration: number;
  constructor(group: string, localGeneration: number, remoteGeneration: number) {
    super(
      `tn.admin rotation conflict on group="${group}": ` +
      `local gen=${localGeneration} vs remote gen=${remoteGeneration}`,
    );
    this.name = "RotationConflictError";
    this.group = group;
    this.localGeneration = localGeneration;
    this.remoteGeneration = remoteGeneration;
  }
}

export class LeafReuseError extends Error {
  readonly group: string;
  readonly leafIndex: number;
  readonly priorRecipientDid: string | null;
  readonly attemptedRecipientDid: string | null;
  constructor(
    group: string,
    leafIndex: number,
    priorRecipientDid: string | null,
    attemptedRecipientDid: string | null,
  ) {
    super(
      `tn.admin leaf-reuse on group="${group}" leaf=${leafIndex}: ` +
      `prior=${priorRecipientDid} attempt=${attemptedRecipientDid}`,
    );
    this.name = "LeafReuseError";
    this.group = group;
    this.leafIndex = leafIndex;
    this.priorRecipientDid = priorRecipientDid;
    this.attemptedRecipientDid = attemptedRecipientDid;
  }
}

export class SameCoordinateForkError extends Error {
  readonly group: string;
  readonly coordinate: string;
  constructor(group: string, coordinate: string) {
    super(`tn.admin same-coordinate fork on group="${group}" coord=${coordinate}`);
    this.name = "SameCoordinateForkError";
    this.group = group;
    this.coordinate = coordinate;
  }
}
