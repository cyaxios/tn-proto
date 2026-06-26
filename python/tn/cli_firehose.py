"""``tn firehose ...`` verbs (gated behind ``TN_FIREHOSE_ENABLED=1``).

Thin client over the Cloudflare ``firehose-worker`` deployment. The verbs are
unmounted by default so a typical CLI user never sees them in ``tn --help``;
only operators who opt in with ``TN_FIREHOSE_ENABLED=1`` get the surface
(``build_parser`` calls :func:`_register_firehose_subcommands` only when
:func:`_firehose_enabled` is true at parser-construction time).

Required env:
    TN_FIREHOSE_ENABLED=1          gate flag (presence of any verb)
    TN_FIREHOSE_URL=<https://...>  base URL of the worker, no trailing /

Optional env:
    TN_FIREHOSE_TOKEN=<bearer>     required by /api/v1/inbox/* routes
                                   (issued by the worker's
                                   /api/v1/auth/verify endpoint)

Tenant -> DID mapping:
    v1 assumes ``did == tenant`` for the inbox routes. The worker's /firehose
    and /stats routes take an opaque tenant id (any alphanumeric, 1..64
    chars); the /api/v1/inbox/* routes require a ``did:key:<...>`` shape and
    check it against the bearer token's bound DID. Callers can override with
    ``--did`` on list/get if their tenant id is not the literal DID.
    TODO: project-id-based tenants once routes_account_projects' DID binding
    is the public mapping.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx

from .cli_common import _die


def _firehose_base() -> str:
    base = (os.environ.get("TN_FIREHOSE_URL") or "").rstrip("/")
    if not base:
        _die(
            "TN_FIREHOSE_URL is not set. Point it at the firehose-worker "
            "base URL (e.g. https://firehose-worker.<account>.workers.dev)."
        )
    return base


def _firehose_token() -> str | None:
    return os.environ.get("TN_FIREHOSE_TOKEN") or None


def _firehose_headers(*, require_token: bool) -> dict[str, str]:
    headers: dict[str, str] = {"accept": "application/json"}
    token = _firehose_token()
    if token:
        headers["authorization"] = f"Bearer {token}"
    elif require_token:
        _die(
            "TN_FIREHOSE_TOKEN is required for inbox routes. Mint one via "
            "the worker's /api/v1/auth/challenge + /api/v1/auth/verify "
            "handshake."
        )
    return headers


def cmd_firehose_stats(args: argparse.Namespace) -> int:
    base = _firehose_base()
    url = f"{base}/stats/{args.tenant}"
    try:
        resp = httpx.get(url, headers=_firehose_headers(require_token=False), timeout=10.0)
    except httpx.HTTPError as exc:
        _die(f"firehose stats request failed: {exc}")
    if resp.status_code != 200:
        _die(
            f"firehose stats returned {resp.status_code}: {resp.text[:200]}",
            code=2,
        )
    try:
        body = resp.json()
    except ValueError:
        print(resp.text)
        return 0
    print(json.dumps(body, indent=2, sort_keys=True))
    return 0


def cmd_firehose_list(args: argparse.Namespace) -> int:
    base = _firehose_base()
    did = args.did or args.tenant
    url = f"{base}/api/v1/inbox/{did}/incoming"
    try:
        resp = httpx.get(url, headers=_firehose_headers(require_token=True), timeout=15.0)
    except httpx.HTTPError as exc:
        _die(f"firehose list request failed: {exc}")
    if resp.status_code != 200:
        _die(
            f"firehose list returned {resp.status_code}: {resp.text[:200]}",
            code=2,
        )
    try:
        body = resp.json()
    except ValueError:
        print(resp.text)
        return 0
    print(json.dumps(body, indent=2, sort_keys=True))
    return 0


def cmd_firehose_get(args: argparse.Namespace) -> int:
    base = _firehose_base()
    did = args.did or args.tenant
    url = f"{base}/api/v1/inbox/{did}/snapshots/{args.ceremony}/{args.name}"
    try:
        resp = httpx.get(url, headers=_firehose_headers(require_token=True), timeout=60.0)
    except httpx.HTTPError as exc:
        _die(f"firehose get request failed: {exc}")
    if resp.status_code != 200:
        _die(
            f"firehose get returned {resp.status_code}: {resp.text[:200]}",
            code=2,
        )
    data = resp.content
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(data)
        print(f"wrote {len(data)} bytes to {out_path}")
    else:
        sys.stdout.buffer.write(data)
    return 0


def _firehose_enabled() -> bool:
    return os.environ.get("TN_FIREHOSE_ENABLED") == "1"


def _register_firehose_subcommands(sub: argparse._SubParsersAction) -> None:
    """Attach the ``tn firehose ...`` verb group when gated on.

    Called from ``build_parser`` only when ``TN_FIREHOSE_ENABLED=1`` at
    parser-construction time. When unset, the verb is invisible to
    ``tn --help`` and dispatch — same shape as ``TN_DEV_AUTH_BYPASS`` on
    the vault server.
    """
    p_fh = sub.add_parser(
        "firehose",
        help="Firehose worker probes (gated by TN_FIREHOSE_ENABLED=1).",
    )
    fhsub = p_fh.add_subparsers(dest="fhverb", required=True)

    p_stats = fhsub.add_parser(
        "stats", help="GET /stats/<tenant> from the firehose worker."
    )
    p_stats.add_argument("tenant", help="Tenant id known to the worker.")
    p_stats.set_defaults(func=cmd_firehose_stats)

    p_list = fhsub.add_parser(
        "list",
        help="List tnpkg snapshots in the worker inbox for <tenant>.",
    )
    p_list.add_argument("tenant", help="Tenant id; assumed to be the DID by default.")
    p_list.add_argument(
        "--did",
        default=None,
        help="Override the DID used for the inbox path (default: tenant).",
    )
    p_list.set_defaults(func=cmd_firehose_list)

    p_get = fhsub.add_parser(
        "get",
        help="Download a single tnpkg snapshot by ceremony + name.",
    )
    p_get.add_argument("tenant", help="Tenant id; assumed to be the DID by default.")
    p_get.add_argument("ceremony", help="Ceremony id segment in the inbox path.")
    p_get.add_argument("name", help="Snapshot file name (e.g. snap.tnpkg).")
    p_get.add_argument(
        "--did",
        default=None,
        help="Override the DID used for the inbox path (default: tenant).",
    )
    p_get.add_argument(
        "--out",
        default=None,
        help="Write bytes to this path instead of stdout.",
    )
    p_get.set_defaults(func=cmd_firehose_get)
