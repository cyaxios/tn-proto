"""Safe-defaults template for auto-created TN ceremonies.

When ``tn.use(name)`` is called against a registry name that does not
yet exist on disk, the SDK auto-creates the ceremony at ``.tn/<name>/``
using this template as the base config. The defaults below are
intentionally the most conservative configuration that still works
out-of-the-box: full evidence guarantees, locally-readable-only, no
leak surface.

The whole point of the safe-defaults invariant is that auto-creation
is friendly without being dangerous. If a future PR relaxes one of
these defaults, that is an explicit decision and it should land with
a written rationale alongside the change. Reviewers: please push back
on any change here that does not document the why.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# The default ceremony's filesystem-registry name. The bare module-level
# API (``tn.info(...)`` etc.) is sugar for ``tn.use("default").info(...)``.
# Reserved: nothing else is allowed to occupy this slot in ``.tn/``.
# ---------------------------------------------------------------------------
DEFAULT_CEREMONY_NAME = "default"


# ---------------------------------------------------------------------------
# The legacy single-ceremony layout placed every ceremony at ``.tn/tn/``.
# On first multi-ceremony-aware init, that directory is migrated to
# ``.tn/default/``. See ``_layout.migrate_legacy_layout``.
# ---------------------------------------------------------------------------
LEGACY_DEFAULT_DIRNAME = "tn"


# ---------------------------------------------------------------------------
# The conservative profile applied to every auto-created ceremony.
# ``transaction`` means signed + chained + durable. We pick the strongest
# guarantee on every axis so an auto-create can never silently downgrade
# the evidence contract a caller might assume. Picking a weaker default
# would mean ``tn.use("audit_trail")`` could silently land on a ceremony
# with weaker guarantees than the name implies.
# ---------------------------------------------------------------------------
DEFAULT_PROFILE = "transaction"


# ---------------------------------------------------------------------------
# The default cipher. ``btn`` is the broadcast-encryption cipher used by
# the protocol's main path. The auto-created ceremony uses it for parity
# with everything else; do not change without coordinating with the
# cipher selection in ``logger.create_fresh``.
# ---------------------------------------------------------------------------
DEFAULT_CIPHER = "btn"


# ---------------------------------------------------------------------------
# The default policy on the only group is ``private``. Combined with a
# recipients list of ``[<local device DID>]``, this means every entry in
# the auto-created ceremony is readable only by the local device. There
# is no leak surface, by design: nothing escapes until the user runs
# ``grant`` to add a recipient.
# ---------------------------------------------------------------------------
DEFAULT_POLICY = "private"


def safe_defaults_yaml(*, device_did: str) -> dict[str, Any]:
    """Return the safe-defaults YAML body as a Python dict, stamped with
    the supplied device DID as the only recipient on the default group.

    Caller is responsible for serializing this to ``.tn/<name>/tn.yaml``.
    The dict is fresh on every call so callers may safely mutate it
    before writing.

    The keys included here are deliberately minimal. Anything not set
    here picks up the SDK's hard-coded fallbacks at config-load time;
    that keeps the on-disk YAML readable and audit-friendly. If a key
    is absent from this template, that is intentional — it is either
    not user-meaningful at auto-create time, or its absence selects a
    safer default than any explicit value would.
    """
    return {
        # Ceremony block: identity, profile, cipher.
        # ``id`` is intentionally not stamped here; ``logger.create_fresh``
        # mints it at first init so its lifetime starts at the on-disk
        # write, not at template-construction time.
        "ceremony": {
            "profile": DEFAULT_PROFILE,
            "cipher": DEFAULT_CIPHER,
        },

        # Default policy applies to every group that does not override
        # it. ``private`` means recipients-only: nothing leaves the
        # device unless explicitly granted out.
        "default_policy": DEFAULT_POLICY,

        # The single default group. The device-self recipient list is
        # the load-bearing safety property — until ``grant`` runs, the
        # only reader is the writer.
        "groups": {
            "default": {
                "policy": DEFAULT_POLICY,
                "cipher": DEFAULT_CIPHER,
                "recipients": [
                    {"recipient_identity": device_did},
                ],
            },
        },

        # Public fields: the minimum useful set so logs are readable
        # at all without granting access. Identical to what the legacy
        # template shipped; kept here so the auto-created ceremony has
        # an inspectable envelope shape from line one.
        "public_fields": [
            "timestamp",
            "event_id",
            "event_type",
            "level",
            "server_did",
            "user_did",
            "request_id",
            "method",
            "path",
        ],
    }


__all__ = [
    "DEFAULT_CEREMONY_NAME",
    "DEFAULT_CIPHER",
    "DEFAULT_POLICY",
    "DEFAULT_PROFILE",
    "LEGACY_DEFAULT_DIRNAME",
    "safe_defaults_yaml",
]
