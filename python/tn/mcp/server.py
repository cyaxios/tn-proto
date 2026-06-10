"""The unified TN MCP server.

One FastMCP process exposing three tool families over Model Context Protocol:

  - Exhaust governance pipeline (tn.mcp.exhaust): the defensible-process
    stages (profile, inventory, template mining, kit matching, per-field
    classification, linkage, hook emission) plus the durable group registry
    and the report assembler.
  - Vault connector (tn.mcp.vault_tools): start/bind local packages with the
    cold-claim flow and pull entitled kits from the vault (read side).
  - Core verbs (tn.mcp.tools_core): tn_status / tn_read / tn_decrypt over the
    active ceremony.

Run:
    python -m tn.mcp                  # stdio (spawned and owned by the agent)
    python -m tn.mcp http             # standalone streamable-http server
    tn-mcp-server [http]              # console script equivalent

For the iteration loop use HTTP: the server is your own process on a localhost
port (TN_MCP_PORT, default 8731), so you can Ctrl+C and relaunch it to pick up
code changes without restarting the coding agent - it reconnects on the next
tool call. (stdio is spawned and owned by the agent, so it is tied to the
agent's lifecycle.)

SECURITY POSTURE (v1): the local keystore is plaintext at rest - anything that
can read the user's files can read the recipient kits, and these tools decrypt
with them by design. A stdio server runs as a child of the spawning agent and
inherits that agent's filesystem access, so it exposes no privilege the agent
does not already hold. There are no per-tool scope gates in v1: every
registered tool is callable by any connected client; the HTTP transport binds
to 127.0.0.1 only.

Each tool is a thin wrapper over a function in tn.mcp.exhaust,
tn.mcp.vault_tools, or tn.mcp.tools_core.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys

from mcp.server.fastmcp import FastMCP

from . import __version__
from . import exhaust as stages
from . import vault_tools as _vs
from .schemas import DecryptInput, ReadInput
from .tools_core import tn_decrypt_impl, tn_read_impl, tn_status_impl

logger = logging.getLogger("tn.mcp.server")

HOST = "127.0.0.1"


def _port_from_env() -> int:
    """Port for the standalone HTTP transport: TN_MCP_PORT, falling back to
    the legacy KYE_PORT, then 8731. A malformed value logs a warning and uses
    the default rather than failing the import."""
    raw = os.environ.get("TN_MCP_PORT") or os.environ.get("KYE_PORT") or "8731"
    try:
        return int(raw)
    except ValueError:
        logger.warning(
            "invalid TN_MCP_PORT/KYE_PORT value %r; using default 8731", raw
        )
        return 8731


PORT = _port_from_env()

mcp = FastMCP("tn-mcp-server", host=HOST, port=PORT)


# --- exhaust governance pipeline (tn.mcp.exhaust) ----------------------------

@mcp.tool()
def inventory_exhaust(source: str, event_key: str = "event_type",
                      granularity: int = 2, families: dict | None = None) -> dict:
    """CATEGORIZE stage. Enumerate every event type and field from an exhaust
    source: a path to JSON-lines OR plain-text logs (any shape). The coverage
    denominator - run first so you can claim you looked at everything.

    Plain-text event-typing, increasing power:
      - `granularity`: leading-word typing knob (lower = coarser).
      - `families`: a {cluster_id: family_name} map from YOUR clustering of
        mine_templates output. When set, lines are typed by Drain cluster ->
        family, so the whole pipeline keys on your families. Pass the same map
        to linkage_graph.

    Returns record_count, format, categories, events{...}, and `decisions` -
    checkpoints to surface to the user before proceeding.
    """
    return stages.inventory_exhaust(source, event_key=event_key,
                                    granularity=granularity, families=families)


@mcp.tool()
def profile(source: str, sample: int = 200) -> dict:
    """PROFILE (run first on plain text). Sniff the log format/delimiter from a
    sample so parsing is informed, not guessed: detects JSON, syslog, delimited
    (pipe/tab/semicolon, with column count), logfmt/kv, or free text. Returns the
    plan + a `decisions` checkpoint to confirm the detected shape. inventory_exhaust
    auto-applies this, but call it to show the user what was detected."""
    return stages.profile(source, sample=sample)


@mcp.tool()
def mine_templates(source: str, sim_th: float = 0.4, depth: int = 4) -> dict:
    """CATEGORIZE (deep). Drain3 template mining: collapse thousands of raw log
    lines into a SMALL set of clean templates with their <*> slots. Run this
    when the word-typer fragments, or whenever you want precise event templates.
    The returned list is small enough to CLUSTER INTO FAMILIES yourself (the
    agent) - you never have to read the raw lines. `sim_th` lower merges more
    (fewer templates), higher splits more.
    """
    return stages.mine_templates(source, sim_th=sim_th, depth=depth)


@mcp.tool()
def pick_kits(categories: list[str]) -> dict:
    """LENS stage. Match the categories from inventory_exhaust to bundled
    industry kits (fhir-clinical, oauth-oidc, pci-cardholder, ...) so
    classification cites a published standard. Off-scope guard: categories with
    no confident match get no kit. Load each matched kit's .md + .yaml before
    judging its fields.
    """
    return stages.pick_kits(categories)


@mcp.tool()
def classify_fields(inventory: dict) -> dict:
    """ISOLATE stage. Per-field sensitivity, each field judged alone. Consumes
    inventory_exhaust output; returns the classification report emit_hook
    expects. Deterministic - you may accept it or override from context.
    """
    return stages.classify_fields(inventory)


@mcp.tool()
def linkage_graph(source: str, event_key: str = "event_type",
                  families: dict | None = None) -> dict:
    """CONTEXTUALIZE stage. Cross-row re-identification risk: fields whose
    values recur across event types (join keys that thread one entity). A field
    benign in isolation can be person-linking here - route those to identity, not
    analytics, whatever their in-isolation class.

    Pass the same `families` map you gave inventory_exhaust so the event types
    line up (otherwise linkage measures spans over raw template slugs).
    """
    return stages.linkage_graph(source, event_key=event_key, families=families)


@mcp.tool()
def emit_hook(classified: dict, use_registry: bool = False,
              out_dir: str = "") -> dict:
    """HOOK stage. Emit a default-private TN config (kit.yaml + agents.md) from a
    classification report. Only an operational allowlist rides in the clear;
    everything else, including unclassified fields, is encrypted. With
    use_registry=True, persisted overrides/linkage escalations from the durable
    registry are applied first.

    Set out_dir to the project's `.tn/` to WRITE the derived kit there
    (`kye-kit.yaml`); the static tools (tn-lint, tn-annotate) then discover and
    additively include it alongside tn.yaml + extends packs. Returns the config
    text, review flags, and written_to.
    """
    return stages.emit_hook(classified, use_registry=use_registry, out_dir=out_dir)


# --- durable group registry (Unity-Catalog-style classification catalog) ----

@mcp.tool()
def remember_classification(classified: dict) -> dict:
    """Persist a classification report into the durable registry so groups
    accumulate across runs and stay consistent. Respects existing human/linkage
    overrides (a detector pass never downgrades them)."""
    return stages.remember_classification(classified)


@mcp.tool()
def set_field_group(leaf: str, group: str, note: str = "") -> dict:
    """Pin a field to a TN group - a durable human override that survives
    re-runs and wins over future detector passes. Use after reviewing a
    classification you disagree with."""
    return stages.set_field_group(leaf, group, note=note)


@mcp.tool()
def apply_linkage(linkage: dict) -> dict:
    """Escalate every cross-row join key from a linkage_graph result to a
    person-linking group in the registry (beats detector/kit; human still wins)."""
    return stages.apply_linkage(linkage)


@mcp.tool()
def groups_registry() -> dict:
    """Inspect the durable catalog: current group->fields map + full per-field
    snapshot (class, confidence, source, overridden, seen-in event types). This
    is the audit artifact."""
    return stages.groups_registry()


@mcp.tool()
def unwind() -> dict:
    """Undo the most recent override / linkage escalation - the 'unwind' move in
    the checkpoint loop. Restores the field to its prior group (or removes it if
    it was newly added). Call repeatedly to step back through changes."""
    return stages.unwind()


@mcp.tool()
def registry_status() -> dict:
    """Call at the START. Reports what is already in the durable catalog (field
    count, groups, overrides, when last updated). If non-empty and you are
    analyzing a DIFFERENT exhaust source, offer to clear_registry() so stale
    decisions do not leak in."""
    return stages.registry_status()


@mcp.tool()
def clear_registry() -> dict:
    """Wipe the durable catalog (fields + history). Use when switching to a new
    exhaust source. Irreversible - confirm with the user first."""
    return stages.clear_registry()


@mcp.tool()
def report(inventory: dict | None = None, linkage: dict | None = None,
           title: str = "Exhaust governance report",
           protection_state: str = "unknown") -> dict:
    """Assemble report DATA (tables/facts) from the durable catalog (+ optional
    inventory/linkage). Returns {markdown, summary}. YOU write the surrounding
    narrative; the tool only supplies facts and claims NOTHING about protection.

    Set `protection_state` honestly - the analysis is read-only on code and does
    not move data:
      - "on_tn": app already emits through TN (proposed routing refines it).
      - "plaintext": app does NOT emit through TN -> sensitive fields are in the
        clear TODAY; the hook is a target, tn-annotate/a handler is what protects.
      - "unknown": not determined.
    """
    return stages.report(inventory=inventory, linkage=linkage, title=title,
                         protection_state=protection_state)


@mcp.tool()
def decrypt_stream(log: str, tn_yaml: str, keystore: str = "",
                   groups: list[str] | None = None) -> dict:
    """HELPER (privileged, user's own env). Read a TN-encrypted exhaust stream
    into plaintext rows so the isolate/context stages see real values, not
    ciphertext. Needs the tn SDK and the user's keystore.
    """
    return stages.decrypt_stream(log, tn_yaml, keystore=keystore or None, groups=groups)


# --- vault connector (local model: get vault contents into a local package) ---

@mcp.tool()
def new_workstream(name: str, project_dir: str = "", vault_url: str = "",
                   open_browser: bool = True, bind: bool = True) -> dict:
    """Start a NEW local TN package (ceremony) and COLD-CLAIM it to the user's
    vault account. Always uses the cold-claim flow (never a warm attach, which
    can create orphaned projects): it mints a fresh unlinked ceremony, uploads an
    encrypted pending-claim, and tries to OPEN the claim URL in the user's
    browser. Returns the claim_url, vault_id, expires_at, and next_steps - the
    user finishes by signing in + approving the passkey (only they can do that).
    Set bind=False to create the local package without claiming yet. After the
    user claims, call vault_sync(name=...) to pull + absorb entitled kits."""
    return _vs.new_workstream(name, project_dir=project_dir or None,
                              vault_url=vault_url or None,
                              open_browser=open_browser, bind=bind)


@mcp.tool()
def claim(name: str = "", vault_url: str = "", open_browser: bool = True) -> dict:
    """(Re)mint a COLD claim URL for an existing local ceremony and open it in the
    user's browser. Use to bind a ceremony created with bind=False, or to re-open
    a still-live claim (idempotent within the claim TTL). This 'autoclaims' as far
    as possible - it does everything except sign-in + passkey, which only the user
    can do. Returns claim_url + next_steps to relay to the user."""
    return _vs.claim(name=name or None, vault_url=vault_url or None,
                     open_browser=open_browser)


@mcp.tool()
def vault_sync(name: str = "", vault_url: str = "") -> dict:
    """READ side: GET your entitled packages from the vault into the LOCAL
    package - pull the inbox of received kits and absorb them, and sync sealed
    files. After this the local keystore can decrypt everything you are entitled
    to - locally, with no key escrow. Does NOT bind/link a project (that is
    new_workstream/claim, the cold-claim flow). Needs a reachable vault + local
    device identity (returns a clear status if absent)."""
    return _vs.vault_sync(name=name or None, vault_url=vault_url or None)


@mcp.tool()
def vault_status(vault_url: str = "") -> dict:
    """Report the local package + vault link state (ceremonies, identity, linked
    vault/account). Safe to call anytime - call at session start to see what is
    locally available to decrypt."""
    return _vs.vault_status(vault_url=vault_url or None)


# --- core verbs (tn.mcp.tools_core) ------------------------------------------

@mcp.tool()
def tn_status() -> dict:
    """One-shot summary of the active TN ceremony: DID, yaml path, ceremony id,
    cipher, vault link mode, sign/chain flags, Rust runtime, and the configured
    groups with their field membership. Call at session start to see which
    package you are operating on. Never raises: when no ceremony is resolvable
    it returns a clear {error, detail} payload."""
    return tn_status_impl()


@mcp.tool()
def tn_read(inp: ReadInput) -> dict:
    """Read the active ceremony's attested log through tn.read with structured,
    declarative filters: event_type (exact, or prefix with a trailing '*'),
    since/until ISO-8601 bounds, fields_equal, and limit. `verify` passes
    through to tn.read: False (default) returns rows as-is; True or 'raise'
    fails the whole read on the first row that fails a check; 'skip' verifies
    and silently drops failing rows. Returns entries plus honest total_scanned /
    returned / truncated counters."""
    return tn_read_impl(inp)


@mcp.tool()
def tn_decrypt(inp: DecryptInput) -> dict:
    """Decrypt raw TN ndjson lines pasted inline against the local keystore
    (the active ceremony's, or the one named by `yaml`). Bad lines come back as
    per-line entries in `failures` instead of aborting the batch; signature and
    chain validity are reported per decrypted row. Never crashes the host:
    keystore problems return a clear {error: ...} payload."""
    return tn_decrypt_impl(inp)


# --- entry point --------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tn-mcp-server",
        description=(
            "Unified TN MCP server: the exhaust governance pipeline, the "
            "vault connector, and the core tn_status/tn_read/tn_decrypt "
            "verbs over Model Context Protocol. Project-rooted; inherits "
            "CWD from the spawning agent."
        ),
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print server version and exit.",
    )
    parser.add_argument(
        "transport",
        nargs="?",
        default="stdio",
        choices=("stdio", "http", "streamable-http"),
        help=(
            "Transport to serve on: 'stdio' (default; spawned and owned by "
            "the agent) or 'http'/'streamable-http' (standalone server on "
            "127.0.0.1, port from TN_MCP_PORT, default 8731)."
        ),
    )
    args = parser.parse_args(argv)

    if args.version:
        print(__version__)
        return 0

    if args.transport in ("http", "streamable-http"):
        logger.info("starting tn-mcp-server (streamable-http) on %s:%d", HOST, PORT)
        print(
            f"tn-mcp-server on http://{HOST}:{PORT}/mcp "
            f"(Ctrl+C and relaunch to reload; the agent reconnects on the "
            f"next tool call)",
            file=sys.stderr,
        )
        mcp.run(transport="streamable-http")
    else:
        logger.info("starting tn-mcp-server (stdio)")
        mcp.run()  # stdio
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
