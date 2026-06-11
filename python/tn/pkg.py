"""Package verbs: export, absorb, bundle_for_recipient.

Operations on the .tnpkg artifact format — packaging data out of /
into a ceremony.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, overload

if TYPE_CHECKING:
    from .absorb import AbsorbReceipt, AbsorbResult
    from .config import LoadedConfig


def export(*args: Any, **kwargs: Any) -> Path:
    from . import _export_impl
    return _export_impl(*args, **kwargs)


@overload
def absorb(source: Path | str | bytes | bytearray, /) -> AbsorbReceipt: ...
@overload
def absorb(
    cfg: LoadedConfig, source: Path | str | bytes | bytearray, /
) -> AbsorbResult: ...
@overload
def absorb(*, source: Path | str | bytes | bytearray) -> AbsorbReceipt: ...
@overload
def absorb(
    *, cfg: LoadedConfig, source: Path | str | bytes | bytearray
) -> AbsorbResult: ...
def absorb(*args: Any, **kwargs: Any) -> AbsorbReceipt | AbsorbResult:
    from . import _absorb_impl
    return _absorb_impl(*args, **kwargs)


def bundle_for_recipient(*args: Any, **kwargs: Any) -> Path:
    from . import _bundle_for_recipient_impl
    return _bundle_for_recipient_impl(*args, **kwargs)
