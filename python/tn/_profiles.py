"""TN evidence profiles — fixed, SDK-tuned types.

A profile bundles (signing, chaining, flush behavior, default sink) into
a single named type. The catalog below is the source of truth: do not
add a new profile or change a property of an existing one without a
written rationale in the docstring of the affected entry. These are
pre-alpha defaults intended to evolve under regression testing across
hardware/configurations, but the *shape* of the catalog is stable.

Why profiles are fixed
----------------------
A "profile" is the SDK's curated bundle of evidence guarantees. Users
*pick* a profile per stream; they do not compose, extend, or invent
profiles. The reason: profiles encode the security/perf/governance
contract the SDK promises. Letting a user assemble their own bundle
of "signing on, chain off, flush async" puts the contract in their
hands and undermines the protocol guarantees.

Anyone wanting different evidence behavior creates a different stream
with a different profile. If no existing profile fits, that is a
signal for SDK work — propose a new entry here, justify the bundle,
land the regression suite.

Always-on floor
---------------
**Encryption is the unconditional floor.** Every profile encrypts
events to the project's default private group. That guarantee does
not vary across profiles. What varies is *evidence* (signing,
chaining), *durability* (flush), and *sink* (where bytes go).

A profile may turn off signing for performance. The events are still
private; what's missing is non-repudiation and tamper-evidence on
that stream. The marketing line: "every event is private by default."

Catalog (alpha — to be regression-tested across hardware)
---------------------------------------------------------
``transaction`` — signed, chained, file (rotating), fsync.
    The conservative default. Use for grants, revokes, payments,
    agent actions, security events — anything where reconstruction
    and non-repudiation matter.

``audit`` — signed, chained, file (rotating), buffered.
    Normal business events where reconstruction matters but you can
    afford a small flush window for throughput. Same evidence
    guarantee as ``transaction``, weaker durability.

``secure_log`` — signed, no chain, file (rotating), buffered.
    Sensitive application logs where authenticity (signing) matters
    more than sequence (chain). Fewer ordering guarantees, fewer
    chain-coordination costs. Each entry stands alone.

``telemetry`` — unsigned, no chain, stdout, async batch.
    Fast-as-stdlib-logger profile. Encryption still applies but
    signing is dropped to approach zero overhead vs Python's
    builtin ``logging.Logger``. Intended for high-volume traces,
    metrics, and debug noise where evidence is overkill.

    TARGET: near-zero performance impact relative to stdlib logger.
    Will be regression-tested across hardware to validate.

Default profile selection
-------------------------
When ``tn.init(name)`` is called without a ``profile`` kwarg, the
default is ``transaction`` — the same conservative shape today's
single-ceremony SDK uses. Strong defaults; you opt down explicitly.

The bare project default (``tn.init()`` -> ``"default"``) gets the
``transaction`` profile too, unless the user picks otherwise.
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

# Flush semantics. Maps to the runtime's flush behavior on each emit.
#   ``fsync``    — write + fsync after every entry. Maximum durability,
#                  highest per-emit latency.
#   ``buffered`` — write to OS buffer, flush at batch boundaries (size
#                  or time triggered).
#   ``async``    — handler accepts the entry and returns immediately;
#                  background worker drains.
FlushPolicy = Literal["fsync", "buffered", "async"]


@dataclass(frozen=True)
class Profile:
    """A single profile entry. Fields are deliberately minimal — every
    behavior the SDK consults at emit time should derive from these
    five booleans/enums. Adding a sixth means the catalog is growing
    a new axis; pause and reason about whether that axis really is
    profile-shaped before adding it.

    ``encrypts`` is here for symmetry but will always be ``True`` in
    every catalog entry. Listed so the contract is visible at the
    type-system level — anyone proposing a profile with
    ``encrypts=False`` should fail review on the spot.
    """

    name: ProfileName
    encrypts: bool   # Always True. Floor of the protocol.
    signs: bool      # Ed25519 sign each row_hash.
    chains: bool     # Maintain prev_hash → row_hash chain per event_type.
    flush: FlushPolicy
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
        flush="fsync",
        default_sink="file_rotating",
        intended_use=(
            "Grants, revokes, payments, agent actions, security events. "
            "Maximum evidence: signed, chained, durable. Use when "
            "reconstruction and non-repudiation matter."
        ),
    ),
    "audit": Profile(
        name="audit",
        encrypts=True,
        signs=True,
        chains=True,
        flush="buffered",
        default_sink="file_rotating",
        intended_use=(
            "Normal business events where reconstruction matters but "
            "you can afford a small flush window. Same evidence as "
            "transaction; weaker durability."
        ),
    ),
    "secure_log": Profile(
        name="secure_log",
        encrypts=True,
        signs=True,
        chains=False,
        flush="buffered",
        default_sink="file_rotating",
        intended_use=(
            "Sensitive application logs where signing matters more "
            "than sequence. No chain — each entry stands alone. "
            "Cheaper to scale than audit/transaction."
        ),
    ),
    "telemetry": Profile(
        name="telemetry",
        encrypts=True,
        signs=False,
        chains=False,
        flush="async",
        default_sink="stdout",
        intended_use=(
            "Fast-as-stdlib-logger profile. Encryption still applies; "
            "signing is dropped to approach zero overhead. Intended "
            "for high-volume traces, metrics, debug noise where "
            "evidence is overkill. Will be regression-tested for "
            "near-zero perf impact vs Python's logging.Logger."
        ),
    ),
    "stdout": Profile(
        name="stdout",
        encrypts=True,
        signs=False,
        chains=False,
        flush="async",
        default_sink="stdout",
        intended_use=(
            "Dev-friendly default. The profile users reach for when "
            "they just want a logger that prints — no on-disk file, "
            "no signing/chain ceremony, the same shape as Python's "
            "``print()``. Encryption is still on (the protocol floor); "
            "everything else is dialed back. Use for local dev, "
            "notebook scratchpads, demos, and any context where the "
            "user wants ``tn.use(name, profile='stdout')`` to behave "
            "like a familiar logger."
        ),
    ),
}


# ---------------------------------------------------------------------------
# Default profile selection
# ---------------------------------------------------------------------------

DEFAULT_PROFILE: ProfileName = "transaction"
"""The profile picked when ``tn.init(name)`` is called without an
explicit ``profile`` kwarg. Conservative on every axis: signed,
chained, durable, file-sink. Onboarding-as-trust means the bare
default carries every guarantee.

Users opt *down* (telemetry for speed, secure_log for less chain
overhead) explicitly. Never silently degrade evidence."""


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
    "FlushPolicy",
    "Profile",
    "ProfileName",
    "SinkKind",
    "all_profile_names",
    "get",
    "is_known",
]
