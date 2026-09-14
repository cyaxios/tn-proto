"""Named defaults for event signing, chaining, and output sinks.

Ceremony creation applies a selected profile's sign, chain, and sink settings
to its YAML. ``transaction`` is the default; callers select another catalog
entry with ``profile=``. Explicit ceremony settings can override those defaults.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, get_args

# ---------------------------------------------------------------------------
# Profile names (Literal for type safety; SDK-fixed)
# ---------------------------------------------------------------------------

ProfileName = Literal["transaction", "audit", "secure_log", "telemetry", "stdout"]


def all_profile_names() -> tuple[str, ...]:
    """Return the catalog as a tuple of name strings.

    Useful for ``--profile`` CLI choice lists, validation, and tests.
    """
    return get_args(ProfileName)


# ---------------------------------------------------------------------------
# Profile properties
# ---------------------------------------------------------------------------

# Sink kinds the catalog references. Stream config may add additional
# sinks via inheritance / per-stream handlers; this is the *baseline*
# that comes with the profile.
SinkKind = Literal["file_rotating", "stdout"]



@dataclass(frozen=True)
class Profile:
    """One catalog entry with ceremony defaults and a usage description."""

    name: ProfileName
    encrypts: bool   # Always True. Floor of the protocol.
    signs: bool      # Ed25519 sign each row_hash.
    chains: bool     # Maintain prev_hash → row_hash chain per event_type.
    default_sink: SinkKind
    intended_use: str

    def has_replay_surface(self) -> bool:
        """True iff a stream with this profile has a readable backlog.

        ``stdout`` is forward-only; reading "all events ever" requires
        a file or persistent sink. ``read()`` and ``watch()`` on a
        stream whose only effective sink is stdout return empty
        rather than raising — different shape, not an error.
        """
        return self.default_sink == "file_rotating"


# ---------------------------------------------------------------------------
# The catalog
#
# Order is documentation order — most conservative first, most
# performance-tuned last. Add new profiles at the appropriate position
# in this gradient.
# ---------------------------------------------------------------------------

_CATALOG: dict[str, Profile] = {
    "transaction": Profile(
        name="transaction",
        encrypts=True,
        signs=True,
        chains=True,
        default_sink="file_rotating",
        intended_use=(
            "Grants, revokes, payments, agent actions, security events. "
            "Signed and chained. Use when "
            "reconstruction and non-repudiation matter."
        ),
    ),
    "audit": Profile(
        name="audit",
        encrypts=True,
        signs=True,
        chains=True,
        default_sink="file_rotating",
        intended_use=(
            "Business events where reconstruction matters. "
            "Signed and chained, with a rotating file sink."
        ),
    ),
    "secure_log": Profile(
        name="secure_log",
        encrypts=True,
        signs=True,
        chains=False,
        default_sink="file_rotating",
        intended_use=(
            "Sensitive application logs where signing matters more "
            "than sequence. Each entry is signed independently."
        ),
    ),
    "telemetry": Profile(
        name="telemetry",
        encrypts=True,
        signs=False,
        chains=False,
        default_sink="file_rotating",
        intended_use=(
            "Encrypted traces, metrics, and debug events. "
            "Writes to a file and stdout with signing and chaining disabled."
        ),
    ),
    "stdout": Profile(
        name="stdout",
        encrypts=True,
        signs=False,
        chains=False,
        default_sink="stdout",
        intended_use=(
            "Console output for local development, notebooks, and demos. "
            "Private groups stay encrypted; signing and chaining are disabled."
        ),
    ),
}


# ---------------------------------------------------------------------------
# Default profile selection
# ---------------------------------------------------------------------------

DEFAULT_PROFILE: ProfileName = "transaction"
"""Default profile for signed, chained events in a file."""


# ---------------------------------------------------------------------------
# Public lookup
# ---------------------------------------------------------------------------


def get(name: str) -> Profile:
    """Look up a profile by name. Raises ``KeyError`` with a friendly
    message listing the catalog when ``name`` is unknown."""
    p = _CATALOG.get(name)
    if p is None:
        raise KeyError(
            f"unknown profile {name!r}; catalog: {sorted(_CATALOG)}"
        )
    return p


def is_known(name: str) -> bool:
    """True iff ``name`` is a profile in the catalog."""
    return name in _CATALOG


__all__ = [
    "DEFAULT_PROFILE",
    "Profile",
    "ProfileName",
    "SinkKind",
    "all_profile_names",
    "get",
    "is_known",
]
