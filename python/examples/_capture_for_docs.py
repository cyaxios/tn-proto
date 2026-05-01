"""Capture real envelopes for the primer doc.

Runs through a few representative tn.log calls and dumps:
  - the raw on-disk JSON (how an attacker / partner / scraper sees it)
  - the decrypted-and-verified view (how you see it with your keys)

Outputs are written to docs/_captures/*.json so the markdown can cite
them directly. Running this script is how we keep the doc honest —
every JSON block in primer.md came from a real run of this file.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import tn

OUT = Path(__file__).resolve().parents[1] / "docs" / "_captures"
OUT.mkdir(parents=True, exist_ok=True)


def _read_first_line(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.loads(f.readline())


def _capture_hello(ws: Path) -> None:
    tn.flush_and_close()
    tn.init(ws / "tn.yaml")
    tn.info("order.created", order_id="A100", amount=42, currency="USD")
    tn.flush_and_close()
    tn.init(ws / "tn.yaml")
    cfg = tn.current_config()

    log_path = ws / ".tn" / "logs" / "tn.ndjson"
    raw = _read_first_line(log_path)
    (OUT / "01_hello_raw.json").write_text(json.dumps(raw, indent=2), encoding="utf-8")

    for e in tn.read(log_path, cfg, raw=True):
        (OUT / "01_hello_decoded.json").write_text(
            json.dumps(
                {
                    "envelope_public": {
                        k: v for k, v in e["envelope"].items() if k not in e["plaintext"]
                    },
                    "plaintext": e["plaintext"],
                    "valid": e["valid"],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        break
    tn.flush_and_close()


def _capture_with_pii(ws: Path) -> None:
    tn.init(ws / "tn.yaml")
    cfg = tn.current_config()
    cfg = tn.ensure_group(cfg, "pii", fields=["email", "ip", "user_agent", "phone"])
    tn.flush_and_close()
    tn.init(ws / "tn.yaml")

    tn.info(
        "order.checkout",
        order_id="A200",
        amount=4200,
        currency="USD",
        email="alice@example.com",
        ip="10.0.0.17",
    )
    tn.flush_and_close()
    tn.init(ws / "tn.yaml")
    cfg = tn.current_config()

    log_path = ws / ".tn" / "logs" / "tn.ndjson"
    entries = list(tn.read(log_path, cfg, raw=True))
    # take the last entry — the order.checkout with PII
    last = entries[-1]

    # The RAW JSON line from disk, before any decryption.
    with open(log_path, encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    raw = json.loads(lines[-1])
    (OUT / "02_pii_raw.json").write_text(json.dumps(raw, indent=2), encoding="utf-8")

    # Decrypted-and-verified view
    (OUT / "02_pii_decoded.json").write_text(
        json.dumps(
            {
                "envelope_public": {
                    k: v for k, v in last["envelope"].items() if k not in last["plaintext"]
                },
                "plaintext": last["plaintext"],
                "valid": last["valid"],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    tn.flush_and_close()


def _capture_split_groups(ws: Path) -> None:
    tn.init(ws / "tn.yaml")
    cfg = tn.current_config()
    cfg = tn.ensure_group(cfg, "orders", fields=["shipping_address", "tracking_number"])
    cfg = tn.ensure_group(cfg, "pii", fields=["email", "phone", "last_name"])
    tn.flush_and_close()
    tn.init(ws / "tn.yaml")

    tn.info(
        "order.shipped",
        order_id="A300",
        carrier="ups",
        # orders group
        shipping_address="123 Main St, Bristol RI",
        tracking_number="1Z999AA10123456784",
        # pii group
        email="alice@example.com",
        phone="+1-401-555-0100",
        last_name="Rivera",
    )
    tn.flush_and_close()
    tn.init(ws / "tn.yaml")
    cfg = tn.current_config()

    log_path = ws / ".tn" / "logs" / "tn.ndjson"
    with open(log_path, encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    raw = json.loads(lines[-1])
    (OUT / "03_split_raw.json").write_text(json.dumps(raw, indent=2), encoding="utf-8")

    last = list(tn.read(log_path, cfg, raw=True))[-1]
    (OUT / "03_split_decoded.json").write_text(
        json.dumps(
            {
                "envelope_public": {
                    k: v for k, v in last["envelope"].items() if k not in last["plaintext"]
                },
                "plaintext": last["plaintext"],
                "valid": last["valid"],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    tn.flush_and_close()


def _capture_with_context(ws: Path) -> None:
    tn.init(ws / "tn.yaml")
    cfg = tn.current_config()
    cfg = tn.ensure_group(cfg, "pii", fields=["user_did"])
    tn.flush_and_close()
    tn.init(ws / "tn.yaml")

    # Simulate a FastAPI middleware + dependency scenario.
    tn.set_context(
        request_id="req-abc-123",
        method="POST",
        path="/payments",
    )
    tn.update_context(user_did="did:plc:alice-user")
    tn.info("payment.created", amount=9900)

    tn.flush_and_close()
    tn.init(ws / "tn.yaml")
    cfg = tn.current_config()

    log_path = ws / ".tn" / "logs" / "tn.ndjson"
    with open(log_path, encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    raw = json.loads(lines[-1])
    (OUT / "06_context_raw.json").write_text(json.dumps(raw, indent=2), encoding="utf-8")

    last = list(tn.read(log_path, cfg, raw=True))[-1]
    (OUT / "06_context_decoded.json").write_text(
        json.dumps(
            {
                "envelope_public": {
                    k: v for k, v in last["envelope"].items() if k not in last["plaintext"]
                },
                "plaintext": last["plaintext"],
                "valid": last["valid"],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    tn.flush_and_close()


def _capture_public_fields(ws: Path) -> None:
    """YAML-first scenario: order_id / amount / currency are declared
    public, email / ip routed to a `pii` group. Captures the envelope
    so we can show a real top-level public + encrypted group mix."""
    tn.flush_and_close()
    tn.clear_context()  # previous capture scenario set context; don't leak it
    tn.init(ws / "tn.yaml")

    # Extend the YAML directly, the way a user would edit it.
    import yaml as _yaml

    doc = _yaml.safe_load((ws / "tn.yaml").read_text(encoding="utf-8"))
    doc["public_fields"] = [
        *(doc.get("public_fields") or []),
        "order_id",
        "amount",
        "currency",
    ]
    doc.setdefault("fields", {})
    doc["fields"]["email"] = {"group": "pii"}
    doc["fields"]["ip"] = {"group": "pii"}
    doc.setdefault("groups", {})["pii"] = {
        "policy": "private",
        "pool_size": 4,
        "recipients": [],
    }
    (ws / "tn.yaml").write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    tn.flush_and_close()
    tn.init(ws / "tn.yaml")
    cfg = tn.current_config()
    cfg = tn.ensure_group(cfg, "pii", fields=["email", "ip"])
    tn.flush_and_close()
    tn.init(ws / "tn.yaml")

    tn.info(
        "order.checkout",
        order_id="A200",
        amount=4200,
        currency="USD",
        email="alice@example.com",
        ip="10.0.0.17",
    )
    tn.flush_and_close()
    tn.init(ws / "tn.yaml")
    cfg = tn.current_config()

    log_path = ws / ".tn" / "logs" / "tn.ndjson"
    with open(log_path, encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    raw = json.loads(lines[-1])
    (OUT / "02_public_raw.json").write_text(json.dumps(raw, indent=2), encoding="utf-8")
    tn.flush_and_close()


def _capture_filetree(ws: Path) -> None:
    """Snapshot the keys/ + logs/ tree the library produces."""
    listing = []
    for p in sorted(ws.rglob("*")):
        if p.is_file():
            rel = p.relative_to(ws).as_posix()
            size = p.stat().st_size
            listing.append(f"{rel}  ({size} bytes)")
    (OUT / "files_after_init.txt").write_text("\n".join(listing), encoding="utf-8")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="capdoc_") as td:
        ws = Path(td)
        _capture_hello(ws)
    with tempfile.TemporaryDirectory(prefix="capdoc_") as td:
        ws = Path(td)
        _capture_with_pii(ws)
    with tempfile.TemporaryDirectory(prefix="capdoc_") as td:
        ws = Path(td)
        _capture_split_groups(ws)
    with tempfile.TemporaryDirectory(prefix="capdoc_") as td:
        ws = Path(td)
        _capture_with_context(ws)
    with tempfile.TemporaryDirectory(prefix="capdoc_") as td:
        ws = Path(td)
        _capture_public_fields(ws)
    with tempfile.TemporaryDirectory(prefix="capdoc_") as td:
        ws = Path(td)
        tn.flush_and_close()
        tn.init(ws / "tn.yaml")
        cfg = tn.current_config()
        tn.ensure_group(cfg, "pii", fields=["email", "ip", "user_agent", "phone"])
        tn.info("app.boot", pid=1234)
        tn.flush_and_close()
        _capture_filetree(ws)

    print(f"captures written to {OUT}")
    for p in sorted(OUT.iterdir()):
        print(f"  {p.name} ({p.stat().st_size} B)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
