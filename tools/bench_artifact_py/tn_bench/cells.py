from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class BenchCell:
    cipher: str
    recipients: int
    payload_bytes: int
    revocation: str = "none"

    @property
    def id(self) -> str:
        return f"{self.cipher}.r{self.recipients}.{payload_label(self.payload_bytes)}.{self.revocation}"


def payload_label(payload_bytes: int) -> str:
    if payload_bytes == 1024:
        return "p1k"
    return f"p{payload_bytes}b"


def make_payload_fields(payload_bytes: int, *, seed: str = "") -> dict[str, str]:
    del seed
    empty = {"payload": ""}
    overhead = len(json.dumps(empty, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    body_len = payload_bytes - overhead
    if body_len < 0:
        raise ValueError(f"payload_bytes={payload_bytes} is too small for the payload envelope")
    fields = {"payload": "x" * body_len}
    actual = len(json.dumps(fields, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    if actual != payload_bytes:
        raise AssertionError(f"payload builder produced {actual} bytes, expected {payload_bytes}")
    return fields


def expand_local_smoke_cells(
    *,
    payloads: Iterable[int] = (64, 256, 1024),
    recipients: Iterable[int] = (1, 4, 8),
    ciphers: Iterable[str] = ("btn", "jwe", "hibe"),
    btn_stress: bool = False,
) -> list[BenchCell]:
    cells: list[BenchCell] = []
    for cipher in ciphers:
        for recipient_count in recipients:
            for payload_bytes in payloads:
                cells.append(BenchCell(cipher, int(recipient_count), int(payload_bytes), "none"))
                if cipher == "btn" and btn_stress:
                    cells.append(
                        BenchCell(cipher, int(recipient_count), int(payload_bytes), "dispersed64")
                    )
    return cells

