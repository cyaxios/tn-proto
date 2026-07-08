"""tn.scope_to(*dids).spawn() — per-DID scoped capability handles.

Mirror of ``ts-sdk/src/scope.ts``. A :class:`ScopedTn` is a read-only view
derived from a seeded ceremony. It opens ONLY the groups where one of the
scoped DIDs is a declared recipient, and leaves every other group sealed.
Reads operate on a handed-in tn stream (``bytes`` or ``str``), so a scoped
handle needs no filesystem of its own — a Worker or governance mesh hands
it the message it received, and it surfaces exactly what those DIDs are
entitled to.

The seeded ceremony is the project publisher and physically holds ciphers
for every group, so the scoping is a capability FILTER (driven by each
group's declared recipient list), not a missing-key accident. That is the
honest custodial property: least privilege per request, even though the
holder could open more.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterable, Iterator
from typing import Any

from . import cipher as _cipher
from ._entry import Entry
from .config import GroupConfig, LoadedConfig
from .reader import _aad_bytes_for


def groups_for_dids(groups: dict[str, GroupConfig], dids: set[str]) -> set[str]:
    """Return the group names that ANY of ``dids`` is a declared recipient of."""
    return {name for name, g in groups.items() if any(d in dids for d in g.recipient_dids)}


class ScopedTn:
    """A read-only capability handle scoped to a fixed set of group names.

    Returned by :meth:`ScopeBuilder.spawn`.
    """

    def __init__(self, cfg: LoadedConfig, allowed: set[str]) -> None:
        self._cfg = cfg
        self._allowed = allowed

    @property
    def groups(self) -> list[str]:
        """Group names this handle is allowed to open, sorted."""
        return sorted(self._allowed)

    def read(self, message: str | bytes) -> Iterator[Entry]:
        """Open a handed-in tn stream.

        ``message`` is the ndjson stream content (the bytes a Worker or mesh
        received, not a file path). Yields one :class:`~tn._entry.Entry` per
        line; only the allowed groups are decrypted, and every other group
        lands in ``entry.hidden_groups``.
        """
        text = message.decode("utf-8") if isinstance(message, (bytes, bytearray)) else message
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                env = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(env, dict):
                continue
            plaintext: dict[str, dict[str, Any]] = {}
            for group in self._allowed:
                g_block = env.get(group)
                if not (isinstance(g_block, dict) and "ciphertext" in g_block):
                    continue
                ct_bytes = base64.b64decode(g_block["ciphertext"])
                try:
                    pt = self._cfg.groups[group].cipher.decrypt(
                        ct_bytes, _aad_bytes_for(env, group)
                    )
                    plaintext[group] = json.loads(pt.decode("utf-8"))
                except _cipher.NotARecipientError:
                    plaintext[group] = {"$no_read_key": True}
                except Exception:  # noqa: BLE001 — decrypt failure stays a marker, never raises
                    plaintext[group] = {"$decrypt_error": True}
            yield Entry.from_raw({"envelope": env, "plaintext": plaintext})


class ScopeBuilder:
    """Builder returned by ``tn.scope_to(...)``.

    Collects the DIDs to scope to; :meth:`spawn` resolves them against the
    config and launches an independent read-only :class:`ScopedTn`.
    """

    def __init__(self, cfg: LoadedConfig, dids: Iterable[str]) -> None:
        self._cfg = cfg
        self._dids = set(dids)

    def spawn(self) -> ScopedTn:
        """Resolve the allowed group set and return the scoped handle."""
        allowed = groups_for_dids(self._cfg.groups, self._dids)
        return ScopedTn(self._cfg, allowed)
