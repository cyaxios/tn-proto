"""Workspace + ceremony builders for scenarios.

Does NOT call tn.init — the Scenario drives that — but produces a
tn.yaml that tn.init can load cleanly.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Workspace:
    root: Path
    keystore: Path
    logs: Path
    yaml_path: Path


def make_workspace(root: Path, name: str) -> Workspace:
    """Create <root>/<name>/.tn/<yaml_stem>/{keys,logs}/ and return a Workspace.

    Per-stem layout: keys and logs live under ``<base>/.tn/<yaml_stem>/`` so
    multiple yamls in the same dir get isolated subtrees. Default yaml is
    ``tn.yaml``, so stem = ``tn`` and paths become ``<base>/.tn/tn/keys`` etc.
    """
    base = root / name
    yaml_stem = "tn"  # tn.yaml is what build_ceremony_yaml emits
    keystore = base / ".tn" / yaml_stem / "keys"
    logs = base / ".tn" / yaml_stem / "logs"
    base.mkdir(parents=True, exist_ok=True)
    keystore.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    return Workspace(
        root=base,
        keystore=keystore,
        logs=logs,
        yaml_path=base / "tn.yaml",
    )


def build_ceremony_yaml(
    ws: Workspace,
    *,
    groups: list[str],
    recipients_per_group: int = 1,
    cipher: str = "jwe",
    context_keys: list[str] | None = None,
    handlers: list[str] | None = None,
) -> Path:
    """Emit a minimal tn.yaml.

    Uses tn.init's implicit ceremony creation for everything it can —
    this function writes only the declarative knobs the scenario cares
    about. tn.init fills in recipient keys at first load.
    """
    handlers = handlers or ["file"]
    lines: list[str] = []
    lines.append("ceremony:")
    lines.append(f"  cipher: {cipher}")
    lines.append(f"  keystore: {ws.keystore.as_posix()}")
    lines.append("  groups:")
    for g in groups:
        lines.append(f"    - name: {g}")
        lines.append(f"      recipients: {recipients_per_group}")
    if context_keys:
        lines.append("context:")
        for k in context_keys:
            lines.append(f"  - {k}")
    lines.append("handlers:")
    for h in handlers:
        lines.append(f"  - {h}")
    ws.yaml_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return ws.yaml_path


def find_free_port() -> int:
    """Ask the OS for an unused TCP port on 127.0.0.1."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
