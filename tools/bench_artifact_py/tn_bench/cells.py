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
    rotation: str = "none"

    @property
    def id(self) -> str:
        base = f"{self.cipher}.r{self.recipients}.{payload_label(self.payload_bytes)}.{self.revocation}"
        if self.rotation != "none":
            return f"{base}.{self.rotation}"
        return base


def payload_label(payload_bytes: int) -> str:
    if payload_bytes == 1024:
        return "p1k"
    if payload_bytes == 3072:
        return "p3k"
    if payload_bytes == 4096:
        return "p4k"
    if payload_bytes == 32768:
        return "p32k"
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


def expand_paper_cells(
    *,
    payloads: Iterable[int] = (64, 256, 1024, 3072, 4096, 32768),
    recipients: Iterable[int] = (1, 4, 8, 32),
    ciphers: Iterable[str] = ("btn", "jwe", "hibe"),
    include_baselines: bool = True,
) -> list[BenchCell]:
    cells: list[BenchCell] = []
    normalized_payloads = [int(payload) for payload in payloads]
    normalized_recipients = [int(recipient_count) for recipient_count in recipients]

    if include_baselines:
        for payload_bytes in normalized_payloads:
            cells.append(BenchCell("plaintext", 0, payload_bytes, "none"))
            cells.append(BenchCell("signchain", 0, payload_bytes, "none"))

    for cipher in ciphers:
        if cipher == "btn":
            for recipient_count in normalized_recipients:
                for payload_bytes in normalized_payloads:
                    for revocation in ("none", "clustered", "dispersed"):
                        for rotation in ("pre_rotation", "post_rotation"):
                            cells.append(
                                BenchCell(
                                    cipher,
                                    recipient_count,
                                    payload_bytes,
                                    revocation,
                                    rotation,
                                )
                            )
            continue

        for recipient_count in normalized_recipients:
            for payload_bytes in normalized_payloads:
                cells.append(BenchCell(cipher, recipient_count, payload_bytes, "none"))

    return cells

