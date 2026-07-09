"""The key-bag walk spans rotations and ciphers (pure-Python read path).

``read_with_keybag`` (the decrypt path behind ``tn.read(log=...)`` and
the seal/unseal pass-2 walk) must open every group block any key in the
keystore can legitimately open:

  * btn across rotation: rotation archives the prior self-kit as
    ``<group>.btn.mykit.retired.<epoch>``; ``BtnGroupCipher.decrypt``
    walks the active kit plus those archives, so pre-rotation rows keep
    decrypting with no Rust runtime involved.
  * hibe in the bag: an absorbed ``<group>.hibe.sk`` grant joins the
    walk next to the reader's own kits.
  * two ciphers, one group name: the bag holds a candidate LIST per
    group and tries each cipher until one opens the block.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import tn
from tn.reader import read_with_keybag


@pytest.fixture(autouse=True)
def _reset_runtime():
    """Start and end with a closed runtime (releases file handles before
    tmp_path cleanup, which Windows requires) and an empty request
    context."""
    try:
        tn.flush_and_close()
    except Exception:
        pass
    tn.clear_context()
    yield
    try:
        tn.flush_and_close()
    except Exception:
        pass
    tn.clear_context()


def _default_plaintexts(log_path, keystore, *event_types):
    """Map each event_type to the decrypted 'default' bodies of its rows."""
    out: dict[str, list] = {et: [] for et in event_types}
    for entry in read_with_keybag(log_path, keystore):
        et = entry["envelope"]["event_type"]
        if et in out:
            out[et].append(entry["plaintext"].get("default"))
    return out


def test_btn_keybag_spans_rotation(tmp_path):
    """Pre- AND post-rotation btn rows decrypt through the key bag."""
    yaml = tmp_path / "tn.yaml"
    log = tmp_path / "log.ndjson"
    tn.init(yaml, log_path=log, cipher="btn")
    keystore = tn.current_config().keystore
    tn.info("order.created", order_id="PRE", stage="pre")
    tn.admin.rotate("default")
    tn.info("order.created", order_id="POST", stage="post")
    tn.flush_and_close()

    assert list(keystore.glob("default.btn.mykit.retired.*")), (
        "setup broken: rotation should archive the prior kit"
    )

    rows = _default_plaintexts(log, keystore, "order.created")["order.created"]
    ids = {body.get("order_id") for body in rows if isinstance(body, dict)}
    assert ids == {"PRE", "POST"}, (
        f"pre- and post-rotation rows must both decrypt; plaintexts: {rows}"
    )


def test_hibe_grant_joins_the_keybag(tmp_path):
    """An absorbed hibe grant decrypts through the default key bag.

    The reader's own ceremony is btn, so after the absorb the keystore
    holds default.btn.mykit AND default.hibe.{mpk,idpath,sk} — the same
    group name under two ciphers. The bag must try both candidates and
    open the authority's hibe-sealed rows.
    """
    a_yaml = tmp_path / "authority" / "tn.yaml"
    a_log = tmp_path / "authority" / "log.ndjson"
    tn.init(a_yaml, log_path=a_log, cipher="hibe")
    tn.info("governed.entry", secret="for-granted-readers-only")
    kit_path = tmp_path / "reader.tnpkg"
    tn.admin.grant_reader(
        "default",
        reader_did="did:key:z6Mk-reader-stub",
        out_path=kit_path,
    )
    tn.flush_and_close()

    r_yaml = tmp_path / "reader" / "tn.yaml"
    tn.init(r_yaml, log_path=tmp_path / "reader" / "log.ndjson")
    r_keystore = tn.current_config().keystore
    tn.absorb(kit_path)
    tn.flush_and_close()
    assert (r_keystore / "default.hibe.sk").exists()
    assert (r_keystore / "default.btn.mykit").exists(), (
        "setup broken: the reader's own btn ceremony should hold a kit "
        "for the same group name"
    )

    rows = _default_plaintexts(a_log, r_keystore, "governed.entry")["governed.entry"]
    assert len(rows) == 1, rows
    assert isinstance(rows[0], dict) and rows[0].get("secret") == (
        "for-granted-readers-only"
    ), rows


def test_two_ciphers_one_group_bag_opens_both(tmp_path):
    """A keystore with default.btn.mykit AND default.jwe.mykey opens rows
    sealed by either cipher."""
    a_yaml = tmp_path / "a" / "tn.yaml"
    a_log = tmp_path / "a" / "log.ndjson"
    tn.init(a_yaml, log_path=a_log, cipher="btn")
    a_keystore = tn.current_config().keystore
    tn.info("btn.row", x=1)
    tn.flush_and_close()

    b_yaml = tmp_path / "b" / "tn.yaml"
    b_log = tmp_path / "b" / "log.ndjson"
    tn.init(b_yaml, log_path=b_log, cipher="jwe")
    b_keystore = tn.current_config().keystore
    tn.info("jwe.row", y=2)
    tn.flush_and_close()

    bag_dir = tmp_path / "bag"
    bag_dir.mkdir()
    shutil.copy(a_keystore / "default.btn.mykit", bag_dir / "default.btn.mykit")
    shutil.copy(b_keystore / "default.jwe.mykey", bag_dir / "default.jwe.mykey")

    combined = tmp_path / "combined.ndjson"
    combined.write_text(
        a_log.read_text(encoding="utf-8") + b_log.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    got = _default_plaintexts(combined, bag_dir, "btn.row", "jwe.row")
    assert got["btn.row"] and got["btn.row"][0].get("x") == 1, got
    assert got["jwe.row"] and got["jwe.row"][0].get("y") == 2, got


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
