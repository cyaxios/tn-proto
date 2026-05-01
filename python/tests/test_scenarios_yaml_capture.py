from scenarios._harness.yaml_capture import snapshot_yaml


def test_snapshot_copies_bytes_with_default_name(tmp_path):
    src = tmp_path / "tn.yaml"
    src.write_text("ceremony:\n  cipher: jwe\n")
    outdir = tmp_path / "out"
    outdir.mkdir()
    dst = snapshot_yaml(src, outdir)
    assert dst.name == "tn.yaml.snapshot"
    assert dst.read_text().startswith("ceremony:")


def test_snapshot_with_suffix(tmp_path):
    src = tmp_path / "tn.yaml"
    src.write_text("x: 1")
    outdir = tmp_path / "out"
    outdir.mkdir()
    dst = snapshot_yaml(src, outdir, suffix="cell_03")
    assert dst.name == "tn.yaml.cell_03.snapshot"


def test_snapshot_missing_source_writes_stub(tmp_path):
    outdir = tmp_path / "out"
    outdir.mkdir()
    dst = snapshot_yaml(tmp_path / "doesnotexist.yaml", outdir)
    assert dst.exists()
    assert "MISSING" in dst.read_text()
