from __future__ import annotations

import importlib

import pytest


@pytest.mark.parametrize("interactive", [True, False])
def test_login_rejects_unused_interactive_option_before_identity_access(
    monkeypatch, interactive: bool
):
    auth_module = importlib.import_module("tn.auth")

    def identity_must_not_be_loaded():
        pytest.fail("an unsupported option must be rejected before identity access")

    monkeypatch.setattr(auth_module, "_load_or_mint_identity", identity_must_not_be_loaded)
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        auth_module.auth.login(interactive=interactive)
