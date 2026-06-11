from pathlib import Path

from tn.conventions import (
    ensure_dirs,
    inbox_dir,
    outbox_dir,
    pending_offers_dir,
    tnpkg_filename,
)


# Per-stem layout (post-`ad1949db`): inbox/outbox/pending_offers and friends
# live under <yaml_dir>/.tn/<yaml_stem>/<bucket>/. The conventions helpers
# default to yaml_stem="tn" when called with a bare directory (i.e., when
# the canonical tn.yaml is implied).
_STEM = "tn"


def test_directory_paths(tmp_path: Path):
    assert inbox_dir(tmp_path) == tmp_path / ".tn" / _STEM / "inbox"
    assert outbox_dir(tmp_path) == tmp_path / ".tn" / _STEM / "outbox"
    assert pending_offers_dir(tmp_path) == tmp_path / ".tn" / _STEM / "pending_offers"


def test_tnpkg_filename_is_safe():
    name = tnpkg_filename("did:key:z6MkBob", "enrolment", 3)
    assert name.endswith(".tnpkg")
    assert "/" not in name and "\\" not in name
    assert ":" not in name


def test_ensure_dirs_is_idempotent(tmp_path: Path):
    """``ensure_dirs`` is a deprecated no-op (kept source-compatible).

    The eager-create-everything pattern produced ghost directories
    visible to operators (FINDINGS S0.2). Each write site now creates
    only the dirs it actually uses, on demand. This test now just
    verifies ``ensure_dirs`` runs idempotently without raising.
    """
    ensure_dirs(tmp_path)
    ensure_dirs(tmp_path)
    # Intentionally no .is_dir() assertion — the function is documented
    # as a no-op. The directory-shape assertions live in
    # test_directory_paths above.
