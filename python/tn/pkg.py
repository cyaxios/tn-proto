"""Package verbs: export, absorb, bundle_for_recipient.

Operations on the .tnpkg artifact format — packaging data out of /
into a ceremony.
"""
from __future__ import annotations


def export(*args, **kwargs):
    from . import _export_impl
    return _export_impl(*args, **kwargs)


def absorb(*args, **kwargs):
    from . import _absorb_impl
    return _absorb_impl(*args, **kwargs)


def bundle_for_recipient(*args, **kwargs):
    from . import _bundle_for_recipient_impl
    return _bundle_for_recipient_impl(*args, **kwargs)
