import tn._cache_policy as cp


def test_default_is_cache(monkeypatch):
    monkeypatch.delenv("TN_NO_KEY_CACHE", raising=False)
    assert cp.should_cache_key(None) is True
    assert cp.should_cache_key(True) is True


def test_explicit_false_opts_out(monkeypatch):
    monkeypatch.delenv("TN_NO_KEY_CACHE", raising=False)
    assert cp.should_cache_key(False) is False


def test_env_opts_out(monkeypatch):
    monkeypatch.setenv("TN_NO_KEY_CACHE", "1")
    assert cp.should_cache_key(None) is False
    assert cp.should_cache_key(True) is False
