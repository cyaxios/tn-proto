"""End-to-end stdio transport tests: spawn ``python -m tn.mcp`` as a child
process and drive it with the mcp client, exactly as a coding agent would.

Two conversations:

* an empty cwd (no ceremony), proving the tool inventory and the
  containment contract over the wire, and
* the committed jwe fixture ceremony, proving tn_status resolves a real
  ceremony through the cookbook's ./tn.yaml discovery chain.

The ``stdio_client`` context manager owns the child process and
terminates it on exit; the whole conversation runs under an outer
``asyncio.wait_for`` so a wedged child fails the test instead of
hanging CI.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import timedelta
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# The validated tool surface: 20 KYE tools + 3 core verbs. Names are
# byte-faithful to the _lab/exhaust source and must not drift.
EXPECTED_TOOLS = frozenset(
    {
        "apply_linkage",
        "claim",
        "classify_fields",
        "clear_registry",
        "decrypt_stream",
        "emit_hook",
        "groups_registry",
        "inventory_exhaust",
        "linkage_graph",
        "mine_templates",
        "new_workstream",
        "pick_kits",
        "profile",
        "registry_status",
        "remember_classification",
        "report",
        "set_field_group",
        "tn_decrypt",
        "tn_read",
        "tn_status",
        "unwind",
        "vault_status",
        "vault_sync",
    }
)

CONVERSATION_TIMEOUT_S = 120.0
PER_REQUEST_TIMEOUT = timedelta(seconds=60)


def _server_params(cwd: Path) -> StdioServerParameters:
    env = {
        **os.environ,
        "TN_FORCE_PYTHON": "1",
        "TN_NO_STDOUT": "1",
        "TN_NO_LINK": "1",
    }
    env.pop("TN_YAML", None)
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "tn.mcp"],
        cwd=str(cwd),
        env=env,
    )


def _text_of(result) -> str:
    return "".join(c.text for c in result.content if getattr(c, "text", None))


def _payload_of(result) -> dict:
    """Parse the JSON payload a dict-returning tool serialized as text."""
    text = _text_of(result)
    assert text, "tool returned no text content"
    return json.loads(text)


async def _converse_no_ceremony(cwd: Path) -> dict:
    """initialize -> list_tools -> tn_status -> tn_read, in an empty cwd."""
    observed: dict = {}
    async with stdio_client(_server_params(cwd)) as (read_stream, write_stream):
        async with ClientSession(
            read_stream, write_stream, read_timeout_seconds=PER_REQUEST_TIMEOUT
        ) as session:
            init = await session.initialize()
            observed["server_name"] = init.serverInfo.name

            tools = await session.list_tools()
            observed["tool_names"] = sorted(t.name for t in tools.tools)

            status = await session.call_tool("tn_status", {})
            observed["status_is_error"] = status.isError
            observed["status_payload"] = _payload_of(status)

            read = await session.call_tool("tn_read", {"inp": {}})
            observed["read_is_error"] = read.isError
            observed["read_text"] = _text_of(read)
    return observed


async def _converse_with_fixture(cwd: Path) -> dict:
    """tn_status against the jwe fixture ceremony living at ./tn.yaml."""
    observed: dict = {}
    async with stdio_client(_server_params(cwd)) as (read_stream, write_stream):
        async with ClientSession(
            read_stream, write_stream, read_timeout_seconds=PER_REQUEST_TIMEOUT
        ) as session:
            await session.initialize()
            status = await session.call_tool("tn_status", {})
            observed["status_is_error"] = status.isError
            observed["status_payload"] = _payload_of(status)
    return observed


def test_stdio_end_to_end_no_ceremony(tmp_path):
    """The shipped entry point speaks MCP over stdio, exposes the exact
    validated tool set, and stays contained when there is no ceremony."""
    observed = asyncio.run(
        asyncio.wait_for(_converse_no_ceremony(tmp_path), CONVERSATION_TIMEOUT_S)
    )

    assert observed["server_name"] == "tn-mcp-server"
    assert set(observed["tool_names"]) == EXPECTED_TOOLS
    assert len(observed["tool_names"]) == len(EXPECTED_TOOLS) == 23

    # tn_status never errors: no ceremony is data, not an exception.
    assert observed["status_is_error"] is False
    payload = observed["status_payload"]
    assert payload["error"].startswith("No ceremony found")
    assert "detail" in payload

    # tn_read does error, but as one clear line, never a stack trace.
    assert observed["read_is_error"] is True
    read_text = observed["read_text"]
    assert "tn_read failed" in read_text
    assert "no ceremony found" in read_text
    assert "Traceback" not in read_text
    assert len(read_text.strip().splitlines()) == 1


def test_stdio_tn_status_resolves_fixture_ceremony(jwe_ceremony):
    """A child server spawned in a ceremony directory resolves ./tn.yaml
    through the discovery chain and reports the fixture's real shape."""
    observed = asyncio.run(
        asyncio.wait_for(
            _converse_with_fixture(jwe_ceremony.parent), CONVERSATION_TIMEOUT_S
        )
    )

    assert observed["status_is_error"] is False
    payload = observed["status_payload"]
    assert "error" not in payload
    assert payload["cipher"] == "jwe"
    assert payload["did"].startswith("did:key:z6Mk")
    assert payload["ceremony_id"].startswith("local_")
    assert Path(payload["yaml_path"]).name == "tn.yaml"
    groups = {g["name"]: g["fields"] for g in payload["groups"]}
    assert groups["pii"] == ["email", "ip", "user_agent"]
