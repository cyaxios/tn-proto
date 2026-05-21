"""On-disk layout for btn group state — owns the file-naming
conventions, the atomic-write helpers, and the rotation promote dance
(write pending → archive prior as retired → promote pending to active).

Layout per group::

    <keystore>/<group>.btn.state              # active master_seed + bookkeeping
    <keystore>/<group>.btn.mykit              # active self-kit
    <keystore>/<group>.btn.state.retired.<N>  # prior master_seed (epoch N)
    <keystore>/<group>.btn.mykit.retired.<N>  # prior self-kit (epoch N)
    <keystore>/<group>.btn.state.pending      # mid-rotation work area
    <keystore>/<group>.btn.mykit.pending      # mid-rotation work area

The legacy ``.revoked.<unix_ts>`` suffix from 0.4.2-line keystores is
still recognized on read (so upgrading to 0.4.3a1 keeps working) but
never produced when writing. See ``load_legacy_revoked()`` for the
compatibility path.

Pulled out of ``tn.cipher.BtnGroupCipher`` so the disk-layout policy
has one home and so the rotation orchestration in ``tn.admin`` doesn't
have to know about file naming. Mirrored on the Rust side by the
discover_retired_btn_states helper in ``crypto/tn-core/src/runtime.rs``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from ._keystore_backend import atomic_write_bytes


@dataclass(frozen=True)
class KitFiles:
    """One group's on-disk state, as bytes — no parsing."""

    state_bytes: bytes
    self_kit: bytes


class BtnKeystore:
    """File-layout policy for one keystore directory.

    Stateless (every method takes the group name as an argument).
    Cheap to instantiate; pass the same root dir every time.
    """

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------
    # path helpers
    # ---------------------------------------------------------------

    def _state_path(self, group: str) -> Path:
        return self.root / f"{group}.btn.state"

    def _kit_path(self, group: str) -> Path:
        return self.root / f"{group}.btn.mykit"

    def _pending_state_path(self, group: str) -> Path:
        return self.root / f"{group}.btn.state.pending"

    def _pending_kit_path(self, group: str) -> Path:
        return self.root / f"{group}.btn.mykit.pending"

    def _retired_state_path(self, group: str, epoch: int) -> Path:
        return self.root / f"{group}.btn.state.retired.{epoch}"

    def _retired_kit_path(self, group: str, epoch: int) -> Path:
        return self.root / f"{group}.btn.mykit.retired.{epoch}"

    # ---------------------------------------------------------------
    # active state I/O
    # ---------------------------------------------------------------

    def write_active(self, group: str, *, state_bytes: bytes, self_kit: bytes) -> None:
        """Persist the active state + self-kit. Atomic per-file via
        :func:`atomic_write_bytes` (write to ``<path>.tmp`` then rename)."""
        atomic_write_bytes(self._state_path(group), state_bytes)
        atomic_write_bytes(self._kit_path(group), self_kit)

    def load_active(self, group: str) -> KitFiles:
        """Read the active state + self-kit. Raises FileNotFoundError
        if either file is missing — callers should treat that as a
        misconfigured keystore."""
        return KitFiles(
            state_bytes=self._state_path(group).read_bytes(),
            self_kit=self._kit_path(group).read_bytes(),
        )

    # ---------------------------------------------------------------
    # retired state discovery + I/O
    # ---------------------------------------------------------------

    def write_retired_pair(
        self,
        group: str,
        *,
        epoch: int,
        state_bytes: bytes,
        self_kit: bytes,
    ) -> None:
        """Persist a retired (state, kit) pair at the given epoch.

        Called by the rotation promote dance just before swapping the
        pending pair into the active slot. Atomic per-file."""
        atomic_write_bytes(self._retired_state_path(group, epoch), state_bytes)
        atomic_write_bytes(self._retired_kit_path(group, epoch), self_kit)

    def load_retired_states(self, group: str) -> dict[int, KitFiles]:
        """Return retired states keyed by epoch.

        A retired state without a matching retired kit (or vice versa)
        is treated as corrupt and skipped with a warning — both files
        are written together in the rotation promote dance, so a
        half-pair on disk indicates either a crash mid-archive or
        operator tampering. The active state + kit are NOT included
        here — use :meth:`load_active` for that."""
        state_prefix = f"{group}.btn.state.retired."
        kit_prefix = f"{group}.btn.mykit.retired."
        state_files: dict[int, bytes] = {}
        kit_files: dict[int, bytes] = {}
        for entry in self.root.iterdir():
            if not entry.is_file():
                continue
            name = entry.name
            if name.startswith(state_prefix):
                suffix = name[len(state_prefix):]
                try:
                    epoch = int(suffix)
                except ValueError:
                    continue
                state_files[epoch] = entry.read_bytes()
            elif name.startswith(kit_prefix):
                suffix = name[len(kit_prefix):]
                try:
                    epoch = int(suffix)
                except ValueError:
                    continue
                kit_files[epoch] = entry.read_bytes()
        out: dict[int, KitFiles] = {}
        for epoch in sorted(state_files.keys() & kit_files.keys()):
            out[epoch] = KitFiles(
                state_bytes=state_files[epoch],
                self_kit=kit_files[epoch],
            )
        missing_kit = state_files.keys() - kit_files.keys()
        missing_state = kit_files.keys() - state_files.keys()
        if missing_kit:
            logging.getLogger("tn.btn_keystore").warning(
                "retired epochs missing kit files (skipping): %s",
                sorted(missing_kit),
            )
        if missing_state:
            logging.getLogger("tn.btn_keystore").warning(
                "retired epochs missing state files (skipping): %s",
                sorted(missing_state),
            )
        return out

    def load_legacy_revoked(self, group: str) -> list[KitFiles]:
        """Load 0.4.2-line ``.revoked.<unix_ts>`` archives.

        These pre-date the ``.retired.<epoch>`` convention. They don't
        carry an explicit epoch — for reads we don't need one (the
        kit's own header epoch is what matters). Returned ordered by
        the unix timestamp embedded in the filename, oldest first.

        Bridges 0.4.2 → 0.4.3a1 keystores: the new layout doesn't
        produce these files (rotation now writes ``.retired.<N>``
        directly), but operators upgrading from 0.4.2 may have
        existing archives that should still decrypt history."""
        state_prefix = f"{group}.btn.state.revoked."
        kit_prefix = f"{group}.btn.mykit.revoked."
        state_files: dict[str, bytes] = {}
        kit_files: dict[str, bytes] = {}
        for entry in self.root.iterdir():
            if not entry.is_file():
                continue
            name = entry.name
            if name.startswith(state_prefix):
                state_files[name[len(state_prefix):]] = entry.read_bytes()
            elif name.startswith(kit_prefix):
                kit_files[name[len(kit_prefix):]] = entry.read_bytes()
        return [
            KitFiles(state_bytes=state_files[ts], self_kit=kit_files[ts])
            for ts in sorted(state_files.keys() & kit_files.keys())
        ]

    # ---------------------------------------------------------------
    # rotation promote dance — see spec section 6.1 (mid-rotation crash)
    # ---------------------------------------------------------------

    def write_pending(
        self,
        group: str,
        *,
        state_bytes: bytes,
        self_kit: bytes,
    ) -> None:
        """Write the post-rotation state to ``.pending`` paths.

        These are NOT visible to the cipher's active load path. They
        sit on disk until :meth:`promote_pending` atomically swaps them
        in. If a crash interrupts the sequence between this call and
        the promote, :meth:`cleanup_orphan_pending` clears the pending
        files so the next init starts from a consistent state."""
        atomic_write_bytes(self._pending_state_path(group), state_bytes)
        atomic_write_bytes(self._pending_kit_path(group), self_kit)

    def promote_pending(self, group: str, *, retiring_epoch: int) -> None:
        """Swap pending → active.

        Caller contract (the rotation orchestrator in
        :class:`BtnGroupCipher.rotate`):
          1. write_pending  — writes the post-rotation active state +
             self-kit to ``.pending`` paths.
          2. write_retired_pair  — writes the lightweight retired
             snapshot + the old self-kit to
             ``.retired.<retiring_epoch>`` paths. This is the canonical
             archive of the prior generation; the active state files
             on disk are now redundant snapshots of the same data.
          3. promote_pending (this method)  — removes the now-redundant
             active files and renames pending → active. Two atomic
             POSIX renames; the file removals are best-effort idempotent
             (a crash between them is recoverable by the next init's
             cleanup_orphan_pending + re-rotate cycle).

        Refuses if the retired pair is NOT present on disk at the
        expected epoch — that means write_retired_pair didn't run and
        a forward-secret rotation would otherwise lose the prior
        master_seed irrecoverably.

        Refuses if the pending pair is absent — write_pending must have
        succeeded.
        """
        state_active = self._state_path(group)
        kit_active = self._kit_path(group)
        state_pending = self._pending_state_path(group)
        kit_pending = self._pending_kit_path(group)
        state_retired = self._retired_state_path(group, retiring_epoch)
        kit_retired = self._retired_kit_path(group, retiring_epoch)

        if not state_retired.exists() or not kit_retired.exists():
            raise FileNotFoundError(
                f"promote_pending: retired archive for epoch {retiring_epoch} "
                f"missing at {state_retired} / {kit_retired}. "
                f"write_retired_pair() must run before promote_pending() so the "
                f"prior generation's master_seed isn't lost when the active "
                f"files are replaced."
            )
        if not state_pending.exists() or not kit_pending.exists():
            raise FileNotFoundError(
                f"promote_pending: pending pair not found at {state_pending} / "
                f"{kit_pending}. Did write_pending() succeed?"
            )

        # Active files are redundant now (their canonical archive is in
        # .retired.<N>). Remove them so the pending → active rename can
        # land. missing_ok=True covers the recovery case where a prior
        # crashed rotation already removed one but not the other.
        state_active.unlink(missing_ok=True)
        kit_active.unlink(missing_ok=True)
        state_pending.rename(state_active)
        kit_pending.rename(kit_active)

    def cleanup_orphan_pending(self, group: str) -> bool:
        """Remove ``.pending`` files that have no corresponding active swap.

        Called on init to recover from crashes BEFORE the promote
        dance's rename sequence committed. Returns True if anything
        was cleaned up — the caller may want to log it as a recovery
        event."""
        cleaned = False
        for p in (self._pending_state_path(group), self._pending_kit_path(group)):
            if p.exists():
                p.unlink()
                cleaned = True
        return cleaned
