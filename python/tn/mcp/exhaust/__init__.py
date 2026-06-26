"""Know-Your-Exhaust engine: defensible-process stages over application exhaust.

Ported from the proven tn_skills know-your-exhaust server. One function per
stage of the defensible process:

    categorize  -> inventory_exhaust   (enumerate; the coverage denominator)
    lens        -> pick_kits           (match categories to industry kits)
    isolate     -> classify_fields     (per-field sensitivity, in isolation)
    contextualize -> linkage_graph     (cross-row re-identification risk)
    hook        -> emit_hook           (default-private TN config)
    (helper)    -> decrypt_stream      (read a TN-encrypted stream with keys)

Plus the durable registry surface (remember_classification, set_field_group,
apply_linkage, groups_registry, unwind, registry_status, clear_registry), the
format sniffers (profile, mine_templates), and the report assembler. All are
plain library functions with JSON-friendly I/O, so they can be called directly
or wrapped as MCP tools; failures surface as error dicts, never as exceptions
into the host.
"""
from __future__ import annotations

from .stages import (
    apply_linkage,
    classify_fields,
    clear_registry,
    decrypt_stream,
    emit_hook,
    groups_registry,
    inventory_exhaust,
    linkage_graph,
    mine_templates,
    pick_kits,
    profile,
    registry_status,
    remember_classification,
    report,
    set_field_group,
    unwind,
)

__all__ = [
    "apply_linkage",
    "classify_fields",
    "clear_registry",
    "decrypt_stream",
    "emit_hook",
    "groups_registry",
    "inventory_exhaust",
    "linkage_graph",
    "mine_templates",
    "pick_kits",
    "profile",
    "registry_status",
    "remember_classification",
    "report",
    "set_field_group",
    "unwind",
]
