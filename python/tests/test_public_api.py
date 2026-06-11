import tn


def test_new_verbs_exported():
    for name in (
        "offer",
        "compile_enrolment",
    ):
        assert hasattr(tn, name), f"missing export: tn.{name}"


def test_dir_matches_all():
    """``dir(tn)`` should be exactly ``__all__``.

    Without the ``__dir__`` hook, Python enumerates every stdlib name
    we imported at module scope (``Path``, ``Any``, ``logging``,
    ``threading``, ``annotations``, ...) plus every auto-imported
    submodule that isn't part of the documented surface. That leaks
    implementation detail into ``help(tn)``, REPL tab-completion, and
    — most importantly — the signal the TS SDK rebuild reads to know
    what the wire contract is.

    Attribute access still works for anything not in ``__all__``;
    we just don't advertise it. If you ARE adding a new public symbol,
    add it to ``__all__`` in ``tn/__init__.py`` — this test will
    remind you.
    """
    public = sorted(n for n in dir(tn) if not n.startswith("_"))
    declared = sorted(tn.__all__)
    assert public == declared, (
        f"dir(tn) drift from __all__: "
        f"extra={set(public) - set(declared)} missing={set(declared) - set(public)}"
    )


def test_subpackages_exported():
    """tn.admin, tn.pkg, tn.vault, tn.admin.cache must be importable."""
    from tn import admin, pkg, vault
    from tn.admin import cache

    # Public verbs surface check
    assert hasattr(admin, "add_recipient")
    assert hasattr(admin, "revoke_recipient")
    assert hasattr(admin, "rotate")
    assert hasattr(admin, "state")
    assert hasattr(admin, "recipients")
    assert hasattr(admin, "revoked_count")
    assert hasattr(admin, "add_agent_runtime")
    assert hasattr(pkg, "export")
    assert hasattr(pkg, "absorb")
    assert hasattr(pkg, "bundle_for_recipient")
    assert hasattr(vault, "link")
    assert hasattr(vault, "unlink")
    assert hasattr(cache, "cached_admin_state")
    assert hasattr(cache, "cached_recipients")
    assert hasattr(cache, "diverged")
    assert hasattr(cache, "clock")
