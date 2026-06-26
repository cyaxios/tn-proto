"""Account-inbox pull + absorb — the shared two-way-sync DOWN leg.

Moved out of ``cli.py`` so BOTH the CLI (``tn wallet sync``, ``tn init``
warm-attach) and the library init path (``_auto_link_after_init`` ->
``_init_attach.attach_or_sync``) can reconcile the account inbox before
pushing, without the library importing the CLI layer.

``pull_and_absorb`` is the engine: stage the account inbox, absorb each new
snapshot (the merge), and surface INFORMED leaf-reuse (equivocation). The CLI
passes a ``report`` callback to print progress; the library passes ``None``
(quiet / contained — a notebook ``tn.init()`` doesn't narrate the merge).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from .conventions import inbox_dir
from .pkg import absorb as _absorb
from .sync_state import is_account_bound
from .vault_client import VaultClient, resolve_vault_url

if TYPE_CHECKING:
    from .identity import Identity


def _safe_path_seg(seg: str) -> str:
    """Path-sanitize a DID / ceremony_id / ts segment.

    DIDs contain ':' which is illegal in Windows path components, and we don't
    want a malicious server-supplied value to escape the inbox root via '/' or
    '..'. Replace path-reserved chars with '_' and reject anything that walks
    above the inbox root.
    """
    cleaned = seg.replace(":", "_").replace("/", "_").replace("\\", "_")
    if cleaned in ("", ".", "..") or cleaned.startswith(".."):
        raise ValueError(f"unsafe path segment: {seg!r}")
    return cleaned


def _download_account_inbox_snapshot(
    client: VaultClient, *, from_did: str, ceremony_id: str, ts: str
) -> bytes | None:
    """Download the raw .tnpkg body via the account-auth route.

    Returns ``None`` when the vault reports the snapshot is GONE (410) or
    not found (404) - a stale inbox entry the listing still references but
    that has been consumed/expired elsewhere (e.g. by another device). A
    single stale item must never crash the whole pull; the caller skips it.
    """
    path = f"/api/v1/account/inbox/{from_did}/{ceremony_id}/{ts}.tnpkg"
    resp = client._request("GET", path)
    if resp.status_code in (404, 410):
        return None
    client._raise_for_status(resp)
    return resp.content


def stage_account_inbox(
    cfg: Any, identity: "Identity", yaml_path: Path
) -> tuple[list[Path], int] | None:
    """Pull the account-scoped inbox and STAGE new snapshots locally.

    Reuses the dashboard's account aggregator (``GET /api/v1/account/inbox``)
    — every snapshot addressed to any DID in ``accounts.minted_dids[]`` for
    this account. Each lands at
    ``<inbox_dir>/<from_did>/<ceremony_id>/<ts>.tnpkg``; already-staged files
    are skipped (idempotent).

    Returns ``(staged_paths, skipped_count)``, or ``None`` when this ceremony
    can't pull (no linked vault AND no account binding, or the vault doesn't
    resolve this DID to an account). Caller decides whether None is fatal.
    Closes its own VaultClient; does NOT touch the tn runtime lifecycle.
    """
    _is_linked_fn = getattr(cfg, "is_linked", None)
    ceremony_linked = (
        bool(_is_linked_fn())
        if callable(_is_linked_fn)
        else bool(getattr(cfg, "linked_vault", None))
    )
    if not ceremony_linked and not is_account_bound(yaml_path):
        return None

    # Prefer the CEREMONY's linked vault (where the push goes) over the
    # identity default — otherwise resolve_vault_url() can fall back to a
    # local dev URL and the pull connect-refuses while the push succeeds.
    vault_url = (
        getattr(cfg, "linked_vault", None)
        or identity.linked_vault
        or resolve_vault_url(None)
    )
    client = VaultClient.for_identity(identity, vault_url)
    staged: list[Path] = []
    skipped = 0
    try:
        resp = client._request("GET", "/api/v1/account/inbox")
        if resp.status_code in (401, 403):
            # The vault doesn't resolve this DID to an account.
            return None
        client._raise_for_status(resp)
        listing = resp.json()
        items = listing.get("items") or []
        target_root = inbox_dir(yaml_path)
        for item in items:
            if item.get("consumed_at"):
                # Already absorbed by another device / the dashboard.
                continue
            from_did = item.get("publisher_identity")
            ceremony_id = item.get("ceremony_id")
            ts = item.get("ts")
            if not (
                isinstance(from_did, str)
                and isinstance(ceremony_id, str)
                and isinstance(ts, str)
            ):
                continue

            dest_dir = target_root / _safe_path_seg(from_did) / _safe_path_seg(
                ceremony_id
            )
            dest = dest_dir / f"{ts}.tnpkg"
            if dest.exists():
                skipped += 1
                continue

            body = _download_account_inbox_snapshot(
                client, from_did=from_did, ceremony_id=ceremony_id, ts=ts
            )
            if body is None:
                # Stale/gone inbox entry (410/404) - skip, never crash the pull.
                skipped += 1
                continue
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(body)
            staged.append(dest)
    finally:
        client.close()
    return staged, skipped


def pull_and_absorb(
    cfg: Any,
    identity: "Identity",
    yaml_path: Path,
    *,
    report: Callable[[str], None] | None = None,
) -> int:
    """Pull the account inbox, ABSORB each staged snapshot (the merge), and
    surface any INFORMED leaf-reuse (equivocation) attempts.

    Returns the number of informed equivocations detected (0 when none / when
    the ceremony isn't account-bound). Absorb is idempotent (dedupe by
    row_hash), and the absorb engine keeps revoked leaves revoked regardless —
    a re-add the publisher KNEW was revoked is surfaced via ``report``.

    ``report`` (if given) receives human-readable progress lines; the CLI
    passes ``print``, the library passes ``None`` (quiet).
    """

    def _say(msg: str) -> None:
        if report is not None:
            report(msg)

    staged_result = stage_account_inbox(cfg, identity, yaml_path)
    if staged_result is None:
        _say(
            "  (pull/merge skipped: ceremony not bound to a vault account; "
            "run `tn account connect <code>` to enable two-way sync)"
        )
        return 0

    staged, skipped = staged_result
    absorbed = 0
    informed: list[Any] = []
    for path in staged:
        try:
            receipt = _absorb(path)
        except Exception as e:  # noqa: BLE001 — one bad file shouldn't abort the merge
            _say(f"  WARN absorb failed for {path.name}: {e}")
            continue
        absorbed += int(getattr(receipt, "accepted_count", 0) or 0)
        for c in getattr(receipt, "conflicts", []) or []:
            if getattr(c, "informed", False):
                informed.append(c)

    _say(
        f"  pulled+absorbed {len(staged)} snapshot(s), {absorbed} new event(s)"
        + (f", {skipped} already local" if skipped else "")
    )
    if informed:
        _say(
            f"  ALERT: {len(informed)} INFORMED leaf-reuse (equivocation) "
            f"attempt(s) — a publisher re-added a leaf it knew was revoked:"
        )
        for c in informed:
            rh = (getattr(c, "attempted_row_hash", "") or "")[:16]
            _say(
                f"    group={getattr(c, 'group', '?')} "
                f"leaf={getattr(c, 'leaf_index', '?')} attempted={rh}..."
            )
    return len(informed)


__all__ = ["pull_and_absorb", "stage_account_inbox"]
