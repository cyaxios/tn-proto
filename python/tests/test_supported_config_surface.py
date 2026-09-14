from pathlib import Path

import pytest
import yaml

from tn import classifier, config


def test_fresh_config_contains_working_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("TN_IDENTITY_DIR", str(tmp_path / "identity"))
    cfg = config.create_fresh(tmp_path / "tn.yaml", link=False)
    doc = yaml.safe_load(cfg.yaml_path.read_text(encoding="utf-8"))
    assert "llm_classifier" not in doc
    assert not hasattr(cfg.groups["default"], "pool_size")


def test_registered_classifier_routes_without_model_configuration(monkeypatch):
    monkeypatch.setattr(classifier, "_active", None)
    calls = []

    def classify(field_name, value_type, groups):
        calls.append((field_name, value_type, groups))
        return "finance"

    classifier._register(classify)
    assert classifier._classify("amount", 35, ["default", "finance"]) == "finance"
    assert calls == [("amount", "int", ["default", "finance"])]


@pytest.mark.parametrize("kind", ["otel", "opentelemetry"])
def test_yaml_rejects_unimplemented_handlers(tmp_path, kind):
    from tn.handlers.registry import build_handlers

    with pytest.raises(ValueError, match="unknown handler kind"):
        build_handlers([{"kind": kind}], yaml_dir=Path(tmp_path), default_log_dir=tmp_path)
