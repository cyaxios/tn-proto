from __future__ import annotations

from typing import Iterable


REQUIRED_EMIT_STAGES = {
    "emit:_TOTAL",
    "emit:field_classify",
    "emit:group_encrypt",
    "emit:group_encrypt.sort",
    "emit:group_encrypt.index_token",
    "emit:group_encrypt.canonical_bytes",
    "emit:group_encrypt.cipher",
    "emit:row_hash",
    "emit:sign",
    "emit:envelope_build",
    "emit:file_write",
}

REQUIRED_READ_STAGES = {
    "read:_TOTAL",
    "read:line_parse",
    "read:row_hash_verify",
    "read:signature_verify",
    "read:chain_verify",
    "read:group_decode",
    "read:group_decrypt",
    "read:group_decrypt.cipher",
    "read:group_plaintext_parse",
}


def check_required_stages(
    cell: str,
    op: str,
    stage_rows: Iterable[dict],
    required_stages: set[str],
) -> None:
    seen = {
        row["stage"]
        for row in stage_rows
        if row.get("cell") == cell and row.get("op") == op and int(row.get("count", 0)) > 0
    }
    missing = required_stages - seen
    if missing:
        raise AssertionError(f"{cell} missing {op} stages: {sorted(missing)}")

