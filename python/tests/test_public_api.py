import tn


def test_new_verbs_exported():
    for name in (
        "offer",
        "compile_enrolment",
    ):
        assert hasattr(tn, name), f"missing export: tn.{name}"


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
