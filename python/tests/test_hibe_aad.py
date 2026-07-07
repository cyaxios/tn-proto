"""Per-emit and per-group additional-authenticated-data (AAD) on the hibe
ceremony surface, as one story through the public product API:

  a  emit a hibe record with tn.info(..., aad={...}); read it back and confirm
     the plaintext is recovered AND the public section carries tn_aad
  b  a reader granted the kit opens the same record (aad reconstructed from
     the public echo)
  c  tamper the on-disk tn_aad dict -> read fails row_hash AND the group no
     longer decrypts (sentinel marker, never plaintext)
  d  a group-level aad default declared in the yaml is applied with no
     per-emit argument
  e  a per-emit aad overrides the yaml default (merge semantics)
  f  a record emitted with NO aad is byte-identical shape (no tn_aad key) and
     reads normally
  g  passing aad on a btn ceremony raises the native-limitation error

The AAD dict is bound (authenticated, not encrypted) to the group seal via
the same canonical-bytes routine that feeds row_hash, and echoed into the
public ``tn_aad`` block so any reader reconstructs byte-identical binding
data. Tampering the echo breaks both the AEAD (decryption) and the row_hash.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn  # noqa: E402
import tn.reader  # noqa: E402


def _read_authority(log_path: Path, cfg) -> list[dict]:
    return list(tn.reader.read(log_path, cfg))


def _by_type(entries: list[dict]) -> dict[str, dict]:
    return {e["envelope"]["event_type"]: e for e in entries}


def _inject_group_aad(yaml_path: Path, group: str, aad: dict) -> None:
    """Add a ``groups.<group>.aad`` block to an already-written yaml.

    Uses the yaml the ceremony wrote at init so the rest of the ceremony
    (keystore, device, recipients) stays intact; only the aad default is
    layered on before the next init reloads it.
    """
    import yaml as _yaml

    doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    doc["groups"][group]["aad"] = aad
    yaml_path.write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="hibeaad_") as td:
        ws = Path(td)
        a_yaml = ws / "authority" / "tn.yaml"
        a_log = ws / "authority" / "log.ndjson"
        kit = ws / "reader.tnpkg"

        # --- (a) emit with a per-emit aad; authority reads it back.
        tn.init(a_yaml, log_path=a_log, cipher="hibe")
        assert tn.current_config().cipher_name == "hibe"
        tn.info("oba.filed", note="quarterly OBA", aad={"policy": "finra-oba", "v": "1"})
        tn.admin.grant_reader("default", reader_did="did:key:z6Mk-aad-r1", out_path=kit)
        tn.flush_and_close()

        tn.init(a_yaml, log_path=a_log, cipher="hibe")
        a_cfg = tn.current_config()
        entries = _read_authority(a_log, a_cfg)
        by = _by_type(entries)
        rec = by["oba.filed"]
        assert rec["plaintext"]["default"]["note"] == "quarterly OBA", rec["plaintext"]
        env = rec["envelope"]
        # tn_aad is echoed as the canonical JSON STRING of the {group: dict}
        # map (so a string public field hashes identically across engines).
        assert json.loads(env["tn_aad"]) == {"default": {"policy": "finra-oba", "v": "1"}}, env.get("tn_aad")
        assert rec["valid"]["row_hash"], "row_hash must verify on an aad record"
        assert rec["valid"]["signature"], "signature must verify on an aad record"
        tn.flush_and_close()
        print("(a) authority sealed + reopened a per-emit aad record; tn_aad echoed")

        # --- (b) a granted reader reconstructs the aad from the public echo.
        tn.init(ws / "reader" / "tn.yaml", log_path=ws / "reader" / "log.ndjson")
        r_keystore = tn.current_config().keystore
        tn.absorb(kit)
        tn.flush_and_close()
        got = {
            e["envelope"]["event_type"]: e["plaintext"]["default"]
            for e in tn.reader.read_as_recipient(a_log, r_keystore, group="default")
        }
        assert got["oba.filed"]["note"] == "quarterly OBA", got
        print("(b) granted reader reconstructed aad + opened the body")

        # --- (c) tamper the on-disk tn_aad -> row_hash fails AND no decrypt.
        lines = a_log.read_text(encoding="utf-8").splitlines()
        tampered_lines = []
        for line in lines:
            obj = json.loads(line)
            if obj.get("event_type") == "oba.filed":
                # Flip a bound value inside the canonical-string echo: the
                # reader now reconstructs different bytes, and the string
                # public field changes so row_hash breaks too.
                obj["tn_aad"] = obj["tn_aad"].replace("finra-oba", "tampered")
            tampered_lines.append(json.dumps(obj, separators=(",", ":")))
        a_log.write_text("\n".join(tampered_lines) + "\n", encoding="utf-8")

        tn.init(a_yaml, log_path=a_log, cipher="hibe")
        a_cfg = tn.current_config()
        by = _by_type(_read_authority(a_log, a_cfg))
        rec = by["oba.filed"]
        assert not rec["valid"]["row_hash"], "tampered tn_aad must break row_hash"
        pt = rec["plaintext"]["default"]
        assert pt != {"note": "quarterly OBA"}, "tampered record must NOT yield real plaintext"
        assert "$decrypt_error" in pt or "$no_read_key" in pt, pt
        tn.flush_and_close()
        print("(c) tampered tn_aad broke row_hash AND decryption (sentinel, not plaintext)")

        # --- (d) group-config aad default with no per-emit arg.
        d_yaml = ws / "cfgdefault" / "tn.yaml"
        d_log = ws / "cfgdefault" / "log.ndjson"
        tn.init(d_yaml, log_path=d_log, cipher="hibe")
        tn.flush_and_close()
        _inject_group_aad(d_yaml, "default", {"tenant": "acme", "region": "us"})
        tn.init(d_yaml, log_path=d_log, cipher="hibe")
        d_cfg = tn.current_config()
        assert d_cfg.groups["default"].aad_default == {"tenant": "acme", "region": "us"}
        tn.info("cfg.first", note="uses yaml aad default")
        tn.flush_and_close()

        tn.init(d_yaml, log_path=d_log, cipher="hibe")
        d_cfg = tn.current_config()
        by = _by_type(_read_authority(d_log, d_cfg))
        rec = by["cfg.first"]
        assert rec["plaintext"]["default"]["note"] == "uses yaml aad default", rec["plaintext"]
        assert json.loads(rec["envelope"]["tn_aad"]) == {"default": {"tenant": "acme", "region": "us"}}
        assert rec["valid"]["row_hash"] and rec["valid"]["signature"]
        tn.flush_and_close()
        print("(d) yaml group aad default bound + echoed with no per-emit arg")

        # --- (e) per-emit aad overrides the yaml default (merge semantics).
        tn.init(d_yaml, log_path=d_log, cipher="hibe")
        tn.info("cfg.override", note="override", aad={"region": "eu", "extra": "1"})
        tn.flush_and_close()
        tn.init(d_yaml, log_path=d_log, cipher="hibe")
        d_cfg = tn.current_config()
        by = _by_type(_read_authority(d_log, d_cfg))
        rec = by["cfg.override"]
        # config default {tenant: acme, region: us} merged UNDER per-emit
        # {region: eu, extra: 1} -> region overridden, tenant kept, extra added.
        assert json.loads(rec["envelope"]["tn_aad"]) == {
            "default": {"tenant": "acme", "region": "eu", "extra": "1"}
        }, rec["envelope"]["tn_aad"]
        assert rec["plaintext"]["default"]["note"] == "override"
        assert rec["valid"]["row_hash"] and rec["valid"]["signature"]
        tn.flush_and_close()
        print("(e) per-emit aad overrode the yaml default (per-emit wins per key)")

        # --- (f) a no-aad record has no tn_aad key and reads normally.
        n_yaml = ws / "noaad" / "tn.yaml"
        n_log = ws / "noaad" / "log.ndjson"
        tn.init(n_yaml, log_path=n_log, cipher="hibe")
        tn.info("plain.first", note="no aad here")
        tn.flush_and_close()
        raw = json.loads(
            [line for line in n_log.read_text(encoding="utf-8").splitlines() if line][0]
        )
        assert "tn_aad" not in raw, f"aad-free record must not carry tn_aad: {sorted(raw)}"
        tn.init(n_yaml, log_path=n_log, cipher="hibe")
        n_cfg = tn.current_config()
        by = _by_type(_read_authority(n_log, n_cfg))
        rec = by["plain.first"]
        assert rec["plaintext"]["default"]["note"] == "no aad here"
        assert rec["valid"]["row_hash"] and rec["valid"]["signature"]
        tn.flush_and_close()
        print("(f) aad-free record stays byte-identical shape (no tn_aad) and reads")

        # --- (g) aad now binds on a btn ceremony too (native btn runtime).
        b_yaml = ws / "btn" / "tn.yaml"
        b_log = ws / "btn" / "log.ndjson"
        tn.init(b_yaml, log_path=b_log, cipher="btn")
        tn.info("btn.governed", note="btn body", aad={"policy": "sox-404"})
        tn.flush_and_close()
        tn.init(b_yaml, log_path=b_log, cipher="btn")
        b_cfg = tn.current_config()
        rec = next(
            e for e in tn.reader.read(b_log, b_cfg)
            if e["envelope"]["event_type"] == "btn.governed"
        )
        assert rec["plaintext"]["default"]["note"] == "btn body", rec["plaintext"]
        assert json.loads(rec["envelope"]["tn_aad"]) == {"default": {"policy": "sox-404"}}
        assert rec["valid"]["row_hash"] and rec["valid"]["signature"]
        tn.flush_and_close()
        print("(g) per-emit aad binds on a btn ceremony via the native runtime")

    return 0


def test_hibe_aad() -> None:
    """Pytest entry point — same story as ``main()`` (self-asserting)."""
    assert main() == 0


if __name__ == "__main__":
    sys.exit(main())
