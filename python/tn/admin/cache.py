"""Materialized AdminState cache (LKV).

Per docs/superpowers/plans/2026-04-24-tn-admin-log-architecture.md section 4:
the LKV cache holds a materialized ``AdminState`` plus a vector clock keyed
by ``(did, event_type) -> max sequence``. The on-disk form lives at
``<yaml_dir>/.tn/admin/admin.lkv.json``; the in-memory form is the
``AdminStateCache`` class below.

Why a cache exists at all: ``tn.admin_state()`` re-reads the entire log on
every call. For long-lived processes (e.g. the studio dashboard, vault
sync handlers) that's O(n) work per query. The cache replays incrementally
forward from a saved offset, so the second + Nth calls only do work
proportional to events appended since the last refresh.

Convergence rules (Section 6.1 of the plan):

* ``tn.recipient.added`` events are idempotent under set union — same
  ``row_hash`` means same envelope, dedupe wins.
* ``tn.recipient.revoked`` events are absorbing: once a leaf transitions
  ``active -> revoked``, subsequent ``recipient_added`` events for the same
  ``(group, leaf_index)`` are flagged as ``LeafReuseAttempt`` and excluded
  from ``state.recipients`` (the envelope is still appended to the log —
  signed events are facts; we don't rewrite them).
* ``tn.rotation.completed`` events are monotonic on ``(group, generation)``.
  Two events at the same generation with different ``previous_kit_sha256``
  are flagged as ``RotationConflict``.
* Same-coordinate forks (``(did, event_type, sequence)`` seen twice with
  different ``row_hash``) are flagged as ``SameCoordinateFork``.

All three conflict types appear in ``cache.head_conflicts``. The reducer
itself never raises on them — they are informational signals for
dashboards / strict callers (``cache.diverged()``).

This module is Python-only for now. Rust + TS parity is queued for the
next session.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..config import LoadedConfig
from .log import is_admin_event_type, resolve_admin_log_path

# Bump if the on-disk LKV layout changes incompatibly. Older files with a
# lower version are ignored (the cache rebuilds from the log).
LKV_VERSION = 1


# ---------------------------------------------------------------------------
# Conflict dataclasses
# ---------------------------------------------------------------------------


@dataclass
class LeafReuseAttempt:
    """A ``tn.recipient.added`` envelope arrived for a ``(group, leaf_index)``
    that is already revoked / retired in the local state. The envelope is
    appended to the log (append-only invariant) but does not produce a
    fresh active recipient row.
    """

    group: str
    leaf_index: int
    attempted_row_hash: str
    originally_revoked_at_row_hash: str | None = None

    kind: str = "leaf_reuse_attempt"


@dataclass
class SameCoordinateFork:
    """Two envelopes share ``(did, event_type, sequence)`` but carry
    different ``row_hash``. This is the equivocation primitive in the
    plan: typically caused by two devices holding the same private key
    and emitting independently while offline.
    """

    did: str
    event_type: str
    sequence: int
    row_hash_a: str
    row_hash_b: str

    kind: str = "same_coordinate_fork"


@dataclass
class RotationConflict:
    """Two ``tn.rotation.completed`` envelopes share ``(group, generation)``
    but disagree on ``previous_kit_sha256``. A real fork at the rotation
    layer; the surviving manifest's view of the group's epoch is
    ambiguous.
    """

    group: str
    generation: int
    previous_kit_sha256_a: str
    previous_kit_sha256_b: str

    kind: str = "rotation_conflict"


# Convenience union for type annotations.
ChainConflict = LeafReuseAttempt | SameCoordinateFork | RotationConflict


def _conflict_from_dict(doc: dict[str, Any]) -> ChainConflict | None:
    """Reconstruct a conflict instance from its persisted dict form. Used
    when loading the LKV file off disk."""
    if not isinstance(doc, dict):
        return None
    kind = doc.get("kind")
    try:
        if kind == "leaf_reuse_attempt":
            return LeafReuseAttempt(
                group=str(doc["group"]),
                leaf_index=int(doc["leaf_index"]),
                attempted_row_hash=str(doc["attempted_row_hash"]),
                originally_revoked_at_row_hash=(
                    str(doc["originally_revoked_at_row_hash"])
                    if doc.get("originally_revoked_at_row_hash") is not None
                    else None
                ),
            )
        if kind == "same_coordinate_fork":
            return SameCoordinateFork(
                did=str(doc["did"]),
                event_type=str(doc["event_type"]),
                sequence=int(doc["sequence"]),
                row_hash_a=str(doc["row_hash_a"]),
                row_hash_b=str(doc["row_hash_b"]),
            )
        if kind == "rotation_conflict":
            return RotationConflict(
                group=str(doc["group"]),
                generation=int(doc["generation"]),
                previous_kit_sha256_a=str(doc["previous_kit_sha256_a"]),
                previous_kit_sha256_b=str(doc["previous_kit_sha256_b"]),
            )
    except (KeyError, TypeError, ValueError):
        return None
    return None


# ---------------------------------------------------------------------------
# Empty-state factory — keeps the in-memory + on-disk default identical.
# ---------------------------------------------------------------------------


def _empty_state() -> dict[str, Any]:
    """Return the canonical empty-AdminState dict. Matches the shape that
    ``tn.admin_state()`` returns when no events exist."""
    return {
        "ceremony": None,
        "groups": [],
        "recipients": [],
        "rotations": [],
        "coupons": [],
        "enrolments": [],
        "vault_links": [],
    }


# ---------------------------------------------------------------------------
# LKV path resolution
# ---------------------------------------------------------------------------


def lkv_path_for(cfg: LoadedConfig) -> Path:
    """Return ``<yaml_dir>/.tn/admin/admin.lkv.json``.

    The directory is created lazily by the cache writer on first save.
    Mirrors the layout convention from section 1.1 of the plan.
    """
    return (cfg.yaml_path.parent / ".tn" / "admin" / "admin.lkv.json").resolve()


# ---------------------------------------------------------------------------
# AdminStateCache
# ---------------------------------------------------------------------------


class AdminStateCache:
    """Materialized AdminState cache. One per ceremony / TNRuntime.

    Replays admin envelopes forward from a cached vector clock, derives
    state, and persists to disk so subsequent calls don't re-replay from
    scratch. Idempotent updates; multi-process tolerant via atomic
    temp+rename writes — last-writer-wins on the json. The ``.ndjson``
    is the source of truth; the LKV is a derivable cache.

    See the module docstring for the convergence rules and section 4 of
    the architecture plan for the full design.
    """

    def __init__(self, cfg: LoadedConfig):
        self._cfg = cfg
        self._lkv_path = lkv_path_for(cfg)

        self._state: dict[str, Any] = _empty_state()
        self._clock: dict[tuple[str, str], int] = {}
        self._head_row_hash: str | None = None
        self._at_offset: int = 0
        self._head_conflicts: list[ChainConflict] = []

        # row_hash -> (did, event_type, sequence). Lets us detect
        # same-coordinate forks (two row_hashes for the same coordinate).
        self._coord_to_row_hash: dict[tuple[str, str, int], str] = {}
        # (group, leaf_index) -> revoked-at row_hash. Used to flag
        # leaf-reuse attempts when an `added` arrives for a revoked leaf.
        self._revoked_leaves: dict[tuple[str, int], str | None] = {}
        # (group, generation) -> previous_kit_sha256. Detect rotation conflicts.
        self._rotations_seen: dict[tuple[str, int], str] = {}
        # row_hashes already folded into state; second-seen ones are skipped.
        self._row_hashes: set[str] = set()

        self._load_from_disk()

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def at_offset(self) -> int:
        """Number of admin envelopes replayed into this cache."""
        self._refresh_if_log_advanced()
        return self._at_offset

    @property
    def head_row_hash(self) -> str | None:
        """row_hash of the most recently replayed admin envelope, or None
        if the log is empty."""
        self._refresh_if_log_advanced()
        return self._head_row_hash

    @property
    def head_conflicts(self) -> list[ChainConflict]:
        """All detected conflicts: leaf-reuse attempts, same-coordinate
        forks, rotation conflicts. Informational; the reducer never
        raises on these."""
        self._refresh_if_log_advanced()
        return list(self._head_conflicts)

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def state(self) -> dict[str, Any]:
        """Current materialized AdminState. Auto-refreshes if the log
        has advanced since the last call."""
        self._refresh_if_log_advanced()
        return self._state

    def recipients(
        self, group: str, *, include_revoked: bool = False
    ) -> list[dict[str, Any]]:
        """Cached version of ``tn.recipients()``. Filters
        ``state.recipients`` by group. ``include_revoked=False`` drops
        anything whose ``active_status`` is not ``"active"``."""
        self._refresh_if_log_advanced()
        out: list[dict[str, Any]] = []
        for rec in self._state.get("recipients") or []:
            if rec.get("group") != group:
                continue
            if not include_revoked and rec.get("active_status") != "active":
                continue
            out.append(dict(rec))
        return sorted(out, key=lambda r: r.get("leaf_index", 0))

    def diverged(self) -> bool:
        """True iff any same-coordinate fork has been observed.

        Leaf-reuse attempts and rotation conflicts are also recorded in
        ``head_conflicts`` but do *not* count as a divergence here —
        leaf reuse is a single-writer invariant violation (terminal
        revocation), not two-writer disagreement, and rotation conflicts
        are tracked separately. This matches the plan's framing: forks
        are coordinate-level disagreements between independently-signed
        envelopes from the *same* writer.
        """
        self._refresh_if_log_advanced()
        return any(isinstance(c, SameCoordinateFork) for c in self._head_conflicts)

    def refresh(self) -> int:
        """Force a reload from the underlying log. Returns the number of
        new envelopes ingested. Use after an external writer (another
        process / handler / absorbed snapshot) has appended without
        going through this cache instance.
        """
        before = self._at_offset
        self._replay_forward()
        self._save_to_disk()
        return self._at_offset - before

    def clock(self) -> dict[tuple[str, str], int]:
        """Current vector clock: ``{(did, event_type) -> max sequence}``."""
        self._refresh_if_log_advanced()
        return dict(self._clock)

    # ------------------------------------------------------------------
    # Internal: source paths, replay, persist
    # ------------------------------------------------------------------

    def _source_paths(self) -> list[Path]:
        """Paths to scan for admin envelopes. Mirrors
        ``tn.export._scan_admin_envelopes``: read both the main log and
        the dedicated admin log; dedupe by row_hash."""
        cfg = self._cfg
        admin_log = resolve_admin_log_path(cfg)
        main_log = cfg.resolve_log_path()
        out: list[Path] = []
        if main_log.exists():
            out.append(main_log)
        if admin_log != main_log and admin_log.exists():
            out.append(admin_log)
        return out

    def _total_envelope_count(self) -> int:
        """Sum of admin-event lines across all source logs. Used as the
        "log advanced?" tripwire so an unchanged log skips work."""
        total = 0
        for path in self._source_paths():
            try:
                with path.open("rb") as f:
                    for line in f:
                        s = line.strip()
                        if not s:
                            continue
                        try:
                            doc = json.loads(s)
                        except json.JSONDecodeError:
                            continue
                        et = doc.get("event_type")
                        if isinstance(et, str) and is_admin_event_type(et):
                            total += 1
            except OSError:
                continue
        return total

    def _refresh_if_log_advanced(self) -> None:
        """Cheap check: if the underlying logs have grown beyond
        ``self._at_offset`` worth of admin events, replay forward.
        Expensive paths (full re-replay) are inside ``_replay_forward``.
        """
        # If the cache has zero state and zero events on disk, nothing
        # to do. If it has more than zero on disk and we're behind,
        # replay. The count is a coarse signal — exactly what we need
        # to skip work when nothing has changed.
        if self._total_envelope_count() <= self._at_offset:
            return
        self._replay_forward()
        self._save_to_disk()

    def _replay_forward(self) -> None:
        """Read admin envelopes from disk in chain order and fold each
        new (not-already-seen-by-row_hash) envelope into the materialized
        state. Idempotent: repeated calls without new envelopes are a
        no-op."""
        # Collect every admin envelope across all source logs, deduped
        # by row_hash. We sort by (timestamp, sequence) so the order is
        # stable and matches the log's intended chain order even when
        # two sources interleave.
        envs: list[dict[str, Any]] = []
        seen_in_pass: set[str] = set()
        for path in self._source_paths():
            try:
                with path.open("r", encoding="utf-8") as f:
                    for line in f:
                        s = line.strip()
                        if not s:
                            continue
                        try:
                            env = json.loads(s)
                        except json.JSONDecodeError:
                            continue
                        et = env.get("event_type")
                        if not isinstance(et, str) or not is_admin_event_type(et):
                            continue
                        rh = env.get("row_hash")
                        if not isinstance(rh, str):
                            continue
                        if rh in seen_in_pass:
                            continue
                        seen_in_pass.add(rh)
                        envs.append(env)
            except OSError:
                continue

        # Stable sort by (timestamp, sequence) ONLY — no row_hash tiebreaker.
        # tn.recipient.added and tn.recipient.revoked live on separate
        # per-event-type chains (both sequence=1) and can share a microsecond
        # timestamp, so a row_hash tiebreaker would order them by hash
        # (non-causally). When revoked then sorts before added, the add is
        # misread as a leaf-reuse attempt and the recipient is dropped. A
        # stable sort instead keeps the on-disk append order (added before
        # revoked) for equal keys. Mirrors the TS AdminStateReducer.
        envs.sort(
            key=lambda e: (
                str(e.get("timestamp") or ""),
                int(e.get("sequence") or 0),
            )
        )

        for env in envs:
            self._apply_envelope(env)
        # at_offset is the number of envelopes successfully merged into
        # state — i.e. the size of self._row_hashes after the pass.
        self._at_offset = len(self._row_hashes)

    # ------------------------------------------------------------------
    # Reducer (Python fallback — mirrors `tn.admin_state()` in __init__.py
    # plus the revocation-is-terminal extension from plan section 6.1)
    # ------------------------------------------------------------------

    def _apply_envelope(self, env: dict[str, Any]) -> None:
        """Fold a single admin envelope into self._state.

        Honors revocation-is-terminal: a ``recipient_added`` for a
        ``(group, leaf_index)`` already revoked / retired in state is
        flagged as a ``LeafReuseAttempt`` and not added to
        ``state.recipients``. Same-coordinate forks and rotation
        conflicts are also detected.

        Structure:
          1. Pre-dispatch invariants (fork detection, dedupe, clock,
             head pointer)  ← _observe_envelope()
          2. Per-event-type merge into self._state                    ← _EVENT_HANDLERS dispatch
        """
        rh = env.get("row_hash")
        if not isinstance(rh, str):
            return

        if not self._observe_envelope(env, rh):
            return  # dedupe; observation invariants already applied

        ts = env.get("timestamp")
        et = env.get("event_type")
        handler = self._EVENT_HANDLERS.get(et)
        if handler is not None:
            # The admin envelope shape stores all admin fields at
            # envelope root (DEFAULT_PUBLIC_FIELDS); ``env`` IS the
            # merged dict, no further flattening needed.
            handler(self, env, ts, rh)
        # Unknown admin event_type — already folded into clock by
        # _observe_envelope; no state mutation. Forward-compatible.

    # ------------------------------------------------------------------
    # Pre-dispatch invariants
    # ------------------------------------------------------------------

    def _observe_envelope(self, env: dict[str, Any], rh: str) -> bool:
        """Apply the three pre-dispatch invariants:

        1. Same-coordinate fork detection (runs even on dedupe).
        2. Row-hash dedupe.
        3. Vector clock + head_row_hash bookkeeping (only on first
           sight of an rh).

        Returns ``True`` if the caller should proceed to per-event
        merge; ``False`` if this envelope is a duplicate and should be
        skipped.
        """
        did = env.get("device_identity")
        et = env.get("event_type")
        seq = env.get("sequence")
        if (
            isinstance(did, str)
            and isinstance(et, str)
            and isinstance(seq, int)
        ):
            self._record_coord_fork_if_any(did, et, seq, rh)

        if rh in self._row_hashes:
            return False
        self._row_hashes.add(rh)

        if (
            isinstance(did, str)
            and isinstance(et, str)
            and isinstance(seq, int)
        ):
            key = (did, et)
            if seq > self._clock.get(key, 0):
                self._clock[key] = seq

        self._head_row_hash = rh
        return True

    def _record_coord_fork_if_any(
        self, did: str, et: str, seq: int, rh: str
    ) -> None:
        """If this ``(did, event_type, sequence)`` was previously seen
        with a different row_hash, append one ``SameCoordinateFork``
        conflict. Subsequent re-observations are deduped.
        """
        coord = (did, et, seq)
        existing_rh = self._coord_to_row_hash.get(coord)
        if existing_rh is None:
            self._coord_to_row_hash[coord] = rh
            return
        if existing_rh == rh:
            return
        already_recorded = any(
            isinstance(c, SameCoordinateFork)
            and c.did == did
            and c.event_type == et
            and c.sequence == seq
            for c in self._head_conflicts
        )
        if not already_recorded:
            self._head_conflicts.append(
                SameCoordinateFork(
                    did=did,
                    event_type=et,
                    sequence=seq,
                    row_hash_a=existing_rh,
                    row_hash_b=rh,
                )
            )

    # ------------------------------------------------------------------
    # Per-event-type handlers — one per admin event_type
    # ------------------------------------------------------------------

    def _on_ceremony_init(
        self, env: dict[str, Any], ts: Any, rh: str
    ) -> None:
        self._state["ceremony"] = {
            "ceremony_id": env.get("ceremony_id"),
            "cipher": env.get("cipher"),
            "device_identity": env.get("device_identity") or env.get("device_identity"),
            "created_at": env.get("created_at") or ts,
        }

    def _on_group_added(
        self, env: dict[str, Any], ts: Any, rh: str
    ) -> None:
        self._state["groups"].append({
            "group": env.get("group"),
            "cipher": env.get("cipher"),
            "publisher_identity": env.get("publisher_identity"),
            "added_at": env.get("added_at") or ts,
        })

    def _on_recipient_added(
        self, env: dict[str, Any], ts: Any, rh: str
    ) -> None:
        group = env.get("group")
        leaf = env.get("leaf_index")
        if not isinstance(group, str) or not isinstance(leaf, int):
            return
        # Revocation is terminal: replay onto a revoked/retired leaf
        # is a reuse attempt, not a state add.
        if (group, leaf) in self._revoked_leaves:
            self._head_conflicts.append(
                LeafReuseAttempt(
                    group=group,
                    leaf_index=leaf,
                    attempted_row_hash=rh,
                    originally_revoked_at_row_hash=self._revoked_leaves[(group, leaf)],
                )
            )
            return
        # Double-add onto an active leaf: first add wins, second is reuse.
        for rec in self._state["recipients"]:
            if rec.get("group") == group and rec.get("leaf_index") == leaf:
                self._head_conflicts.append(
                    LeafReuseAttempt(
                        group=group,
                        leaf_index=leaf,
                        attempted_row_hash=rh,
                        originally_revoked_at_row_hash=None,
                    )
                )
                return
        self._state["recipients"].append({
            "group": group,
            "leaf_index": leaf,
            "recipient_identity": env.get("recipient_identity"),
            "kit_sha256": env.get("kit_sha256"),
            "minted_at": ts,
            "active_status": "active",
            "revoked_at": None,
            "retired_at": None,
        })

    def _on_recipient_revoked(
        self, env: dict[str, Any], ts: Any, rh: str
    ) -> None:
        group = env.get("group")
        leaf = env.get("leaf_index")
        if not isinstance(group, str) or not isinstance(leaf, int):
            return
        self._revoked_leaves[(group, leaf)] = rh
        for rec in self._state["recipients"]:
            if (
                rec.get("group") == group
                and rec.get("leaf_index") == leaf
                and rec.get("active_status") == "active"
            ):
                rec["active_status"] = "revoked"
                rec["revoked_at"] = ts

    def _on_rotation_completed(
        self, env: dict[str, Any], ts: Any, rh: str
    ) -> None:
        group = env.get("group")
        generation_raw = env.get("generation")
        try:
            generation = int(generation_raw) if generation_raw is not None else None
        except (TypeError, ValueError):
            generation = None
        prev_kit = env.get("previous_kit_sha256")

        if isinstance(group, str) and generation is not None:
            self._record_rotation_conflict_if_any(group, generation, prev_kit)

        self._state["rotations"].append({
            "group": group,
            "cipher": env.get("cipher"),
            "generation": generation,
            "previous_kit_sha256": prev_kit,
            "rotated_at": env.get("rotated_at") or ts,
        })
        # Retire any currently-active recipients in this group.
        for rec in self._state["recipients"]:
            if (
                rec.get("group") == group
                and rec.get("active_status") == "active"
            ):
                rec["active_status"] = "retired"
                rec["retired_at"] = ts

    def _record_rotation_conflict_if_any(
        self, group: str, generation: int, prev_kit: Any
    ) -> None:
        rot_key = (group, generation)
        if rot_key in self._rotations_seen:
            if (
                isinstance(prev_kit, str)
                and self._rotations_seen[rot_key] != prev_kit
            ):
                self._head_conflicts.append(
                    RotationConflict(
                        group=group,
                        generation=generation,
                        previous_kit_sha256_a=self._rotations_seen[rot_key],
                        previous_kit_sha256_b=prev_kit,
                    )
                )
        elif isinstance(prev_kit, str):
            self._rotations_seen[rot_key] = prev_kit

    def _on_coupon_issued(
        self, env: dict[str, Any], ts: Any, rh: str
    ) -> None:
        self._state["coupons"].append({
            "group": env.get("group"),
            "slot": env.get("slot"),
            "recipient_identity": env.get("recipient_identity"),
            "issued_to": env.get("issued_to"),
            "issued_at": ts,
        })

    def _on_enrolment_compiled(
        self, env: dict[str, Any], ts: Any, rh: str
    ) -> None:
        self._state["enrolments"].append({
            "group": env.get("group"),
            "peer_identity": env.get("peer_identity"),
            "package_sha256": env.get("package_sha256"),
            "status": "offered",
            "compiled_at": env.get("compiled_at") or ts,
            "absorbed_at": None,
        })

    def _on_enrolment_absorbed(
        self, env: dict[str, Any], ts: Any, rh: str
    ) -> None:
        publisher_identity = env.get("publisher_identity")
        group = env.get("group")
        for enr in self._state["enrolments"]:
            if (
                enr.get("group") == group
                and enr.get("peer_identity") == publisher_identity
            ):
                enr["status"] = "absorbed"
                enr["absorbed_at"] = env.get("absorbed_at") or ts
                return
        # Stand-alone absorbed without a prior compile.
        self._state["enrolments"].append({
            "group": group,
            "peer_identity": publisher_identity,
            "package_sha256": env.get("package_sha256"),
            "status": "absorbed",
            "compiled_at": None,
            "absorbed_at": env.get("absorbed_at") or ts,
        })

    def _on_vault_linked(
        self, env: dict[str, Any], ts: Any, rh: str
    ) -> None:
        vd = env.get("vault_identity")
        if not isinstance(vd, str):
            return
        # last-writer-wins on (vault_identity): replace any existing entry.
        self._state["vault_links"] = [
            link for link in self._state["vault_links"]
            if link.get("vault_identity") != vd
        ]
        self._state["vault_links"].append({
            "vault_identity": vd,
            "project_id": env.get("project_id"),
            "linked_at": env.get("linked_at") or ts,
            "unlinked_at": None,
        })

    def _on_vault_unlinked(
        self, env: dict[str, Any], ts: Any, rh: str
    ) -> None:
        vd = env.get("vault_identity")
        if not isinstance(vd, str):
            return
        for link in self._state["vault_links"]:
            if link.get("vault_identity") == vd:
                link["unlinked_at"] = env.get("unlinked_at") or ts

    _EVENT_HANDLERS = {
        "tn.ceremony.init":     _on_ceremony_init,
        "tn.group.added":       _on_group_added,
        "tn.recipient.added":   _on_recipient_added,
        "tn.recipient.revoked": _on_recipient_revoked,
        "tn.rotation.completed": _on_rotation_completed,
        "tn.coupon.issued":     _on_coupon_issued,
        "tn.enrolment.compiled": _on_enrolment_compiled,
        "tn.enrolment.absorbed": _on_enrolment_absorbed,
        "tn.vault.linked":      _on_vault_linked,
        "tn.vault.unlinked":    _on_vault_unlinked,
    }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _serialize_clock(self) -> dict[str, dict[str, int]]:
        """Vector clock keyed by ``did -> {event_type -> seq}`` for JSON.
        The in-memory form uses tuple keys; JSON does not."""
        out: dict[str, dict[str, int]] = {}
        for (did, et), seq in self._clock.items():
            out.setdefault(did, {})[et] = seq
        return out

    def _deserialize_clock(
        self, doc: dict[str, Any]
    ) -> dict[tuple[str, str], int]:
        out: dict[tuple[str, str], int] = {}
        if not isinstance(doc, dict):
            return out
        for did, et_map in doc.items():
            if not isinstance(et_map, dict):
                continue
            for et, seq in et_map.items():
                try:
                    out[(str(did), str(et))] = int(seq)
                except (TypeError, ValueError):
                    continue
        return out

    def _save_to_disk(self) -> None:
        """Atomic temp+rename write of the LKV. No file locks; concurrent
        writers tolerate stale reads (last-writer-wins on the json)."""
        path = self._lkv_path
        path.parent.mkdir(parents=True, exist_ok=True)
        doc = {
            "version": LKV_VERSION,
            "ceremony_id": self._cfg.ceremony_id,
            "clock": self._serialize_clock(),
            "head_row_hash": self._head_row_hash,
            "at_offset": self._at_offset,
            "state": self._state,
            "head_conflicts": [asdict(c) for c in self._head_conflicts],
            # Internal recovery fields — not part of the manifest schema
            # but persisted so a re-instantiated cache can resume without
            # re-replay. The .ndjson is still the source of truth; if the
            # LKV is missing or stale, we rebuild from it.
            "_row_hashes": sorted(self._row_hashes),
            "_revoked_leaves": [
                {"group": g, "leaf_index": li, "row_hash": rh}
                for (g, li), rh in self._revoked_leaves.items()
            ],
            "_rotations_seen": [
                {"group": g, "generation": gen, "previous_kit_sha256": prev}
                for (g, gen), prev in self._rotations_seen.items()
            ],
            "_coord_to_row_hash": [
                {"did": d, "event_type": et, "sequence": seq, "row_hash": rh}
                for (d, et, seq), rh in self._coord_to_row_hash.items()
            ],
        }
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(doc, sort_keys=True, indent=2), encoding="utf-8")
        os.replace(tmp, path)

    def _load_from_disk(self) -> None:
        """Restore in-memory cache state from ``admin.lkv.json`` if it
        exists and is well-formed for this ceremony. On any error or
        ceremony mismatch, fall back to a fresh cache and let the next
        ``_replay_forward`` rebuild from the log."""
        path = self._lkv_path
        if not path.exists():
            return
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        if not isinstance(doc, dict):
            return
        if doc.get("version") != LKV_VERSION:
            return
        if doc.get("ceremony_id") != self._cfg.ceremony_id:
            return

        state = doc.get("state")
        if isinstance(state, dict):
            # Defensive: ensure every list key is present so callers can
            # always iterate without KeyError.
            base = _empty_state()
            base.update({k: state[k] for k in base if k in state})
            self._state = base
        self._clock = self._deserialize_clock(doc.get("clock") or {})
        self._head_row_hash = doc.get("head_row_hash") if isinstance(
            doc.get("head_row_hash"), str
        ) else None
        try:
            self._at_offset = int(doc.get("at_offset", 0))
        except (TypeError, ValueError):
            self._at_offset = 0

        # Conflicts.
        self._head_conflicts = []
        for c in doc.get("head_conflicts") or []:
            obj = _conflict_from_dict(c)
            if obj is not None:
                self._head_conflicts.append(obj)

        # Internal recovery fields. If absent (older file), rebuild from
        # the log on next refresh — they're additive, not load-bearing.
        self._row_hashes = set(doc.get("_row_hashes") or [])
        self._revoked_leaves = {}
        for entry in doc.get("_revoked_leaves") or []:
            try:
                self._revoked_leaves[
                    (str(entry["group"]), int(entry["leaf_index"]))
                ] = (
                    str(entry["row_hash"])
                    if entry.get("row_hash") is not None
                    else None
                )
            except (KeyError, TypeError, ValueError):
                continue
        self._rotations_seen = {}
        for entry in doc.get("_rotations_seen") or []:
            try:
                self._rotations_seen[
                    (str(entry["group"]), int(entry["generation"]))
                ] = str(entry["previous_kit_sha256"])
            except (KeyError, TypeError, ValueError):
                continue
        self._coord_to_row_hash = {}
        for entry in doc.get("_coord_to_row_hash") or []:
            try:
                self._coord_to_row_hash[
                    (
                        str(entry["did"]),
                        str(entry["event_type"]),
                        int(entry["sequence"]),
                    )
                ] = str(entry["row_hash"])
            except (KeyError, TypeError, ValueError):
                continue


# Module-level convenience accessors. Delegate to the runtime singleton
# managed in `tn/__init__.py` (`_get_or_create_cache`, `_cached_admin_state`)
# via late imports so we don't introduce a circular dependency.


def cached_admin_state(*, refresh: bool = False) -> dict[str, Any]:
    """Cached, materialized AdminState. Equivalent shape to
    ``tn.admin.state()`` but persists between calls so the second + Nth
    call don't re-replay the entire log.

    Pass ``refresh=True`` to force a re-read of the underlying log.
    """
    from .. import _get_or_create_cache, _maybe_autoinit_load_only
    _maybe_autoinit_load_only()
    cache = _get_or_create_cache()
    if refresh:
        cache.refresh()
    return cache.state()


def cached_recipients(
    group: str, *, include_revoked: bool = False, refresh: bool = False
) -> list[dict[str, Any]]:
    """Cached version of ``tn.admin.recipients()``."""
    from .. import _get_or_create_cache, _maybe_autoinit_load_only
    _maybe_autoinit_load_only()
    cache = _get_or_create_cache()
    if refresh:
        cache.refresh()
    return cache.recipients(group, include_revoked=include_revoked)


def diverged() -> bool:
    """True iff the admin cache has observed any same-coordinate fork."""
    from .. import _get_or_create_cache
    return _get_or_create_cache().diverged()


def clock() -> dict[tuple[str, str], int]:
    """Vector clock of the admin cache."""
    from .. import _get_or_create_cache
    return _get_or_create_cache().clock()


__all__ = [
    "AdminStateCache",
    "ChainConflict",
    "LeafReuseAttempt",
    "RotationConflict",
    "SameCoordinateFork",
    "cached_admin_state",
    "cached_recipients",
    "clock",
    "diverged",
    "lkv_path_for",
]
