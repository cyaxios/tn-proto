from scenarios._harness.fixtures import (
    build_ceremony_yaml,
    find_free_port,
    make_workspace,
)


def test_workspace_creates_expected_dirs(tmp_path):
    ws = make_workspace(root=tmp_path, name="alice_s01")
    assert ws.root.exists()
    assert ws.keystore.exists()
    assert ws.logs.exists()
    assert ws.yaml_path == ws.root / "tn.yaml"


def test_build_ceremony_yaml_basic_jwe(tmp_path):
    ws = make_workspace(root=tmp_path, name="t")
    path = build_ceremony_yaml(
        ws,
        groups=["pii", "ops"],
        recipients_per_group=3,
        cipher="jwe",
    )
    text = path.read_text()
    assert "cipher: jwe" in text
    assert "pii" in text and "ops" in text


def test_find_free_port_returns_int():
    p = find_free_port()
    assert isinstance(p, int)
    assert 1024 < p < 65536
