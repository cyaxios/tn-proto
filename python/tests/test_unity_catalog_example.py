"""Exercise catalog lookup with local HTTP and actual native TN publications."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import pytest
import tn


EXAMPLE = Path(__file__).resolve().parents[1] / "examples/providers/unity_catalog.py"
VOLUME = "demo.public.greetings"


@pytest.fixture
def example():
    return runpy.run_path(str(EXAMPLE))


@pytest.fixture
def catalog():
    state = {"status": 200, "body": {}, "requests": [], "reason": None, "redirect": None}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state["requests"].append((self.path, self.headers.get("Authorization")))
            body = json.dumps(state["body"]).encode("utf-8")
            self.send_response(state["status"], state["reason"])
            if state["redirect"]:
                self.send_header("Location", state["redirect"])
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield SimpleNamespace(url=f"http://127.0.0.1:{server.server_port}", state=state)
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


@pytest.fixture
def prepared(example, catalog, tmp_path):
    workspace = tmp_path / "workspace"
    location = example["prepare"](workspace)
    catalog.state["body"] = {"full_name": VOLUME, "storage_location": location}
    return workspace


def test_commands_reopen_persisted_keys_after_catalog_http_lookup(catalog, tmp_path):
    workspace = tmp_path / "command-workspace"
    setup = subprocess.run(
        [sys.executable, "-B", str(EXAMPLE), "prepare", str(workspace)],
        capture_output=True, text=True,
    )
    assert setup.returncode == 0, setup.stderr
    location = (workspace / "publications").as_uri()
    assert setup.stdout.splitlines()[-1] == location
    assert [path.name for path in (workspace / "publications").iterdir()] == ["greeting.tn"]
    wire = (workspace / "publications/greeting.tn").read_bytes()
    assert b"Hello, world!" not in wire
    publication = tn.GovernedObject.parse(wire)
    pin = json.loads((workspace / "private/expected-publication.json").read_text(encoding="utf-8"))
    assert pin["publication_id"] == publication.id
    assert set(publication.group_names) == {"messages", "tn.agents"}
    catalog.state["body"] = {"full_name": VOLUME, "storage_location": location}
    environment = os.environ.copy()
    environment["TN_UNITY_TOKEN"] = "local-test-token"
    result = subprocess.run(
        [sys.executable, "-B", str(EXAMPLE), "read", str(workspace),
         "--url", catalog.url, "--volume", VOLUME],
        capture_output=True, text=True, env=environment,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["Hello, world!"]
    assert catalog.state["requests"] == [
        ("/api/2.1/unity-catalog/volumes/demo.public.greetings", "Bearer local-test-token")
    ]


@pytest.mark.parametrize("field", ["full_name", "storage_location"])
def test_catalog_mismatch_is_refused_before_publication_file_read(example, prepared, catalog, field):
    (prepared / "publications/greeting.tn").unlink()
    catalog.state["body"][field] = (
        "other.public.greetings" if field == "full_name" else (prepared / "private").as_uri()
    )
    with pytest.raises(ValueError, match=field):
        example["read"](prepared, url=catalog.url, volume=VOLUME)


@pytest.mark.parametrize("advertise_target", [False, True])
def test_redirected_publication_directory_is_refused_even_with_valid_signed_file(
    example, prepared, catalog, advertise_target,
):
    publications = prepared / "publications"
    redirected = prepared / "redirected-publications"
    publications.rename(redirected)
    try:
        publications.symlink_to(redirected, target_is_directory=True)
    except OSError as error:
        if os.name == "nt" and getattr(error, "winerror", None) == 1314:
            pytest.skip("Windows symlink creation requires an unavailable privilege")
        raise
    if advertise_target:
        catalog.state["body"]["storage_location"] = redirected.as_uri()
    with pytest.raises(ValueError, match="storage_location|fixed"):
        example["read"](prepared, url=catalog.url, volume=VOLUME)


def test_another_valid_publication_cannot_replace_the_pinned_one(example, prepared, catalog):
    session, policy = example["configure"](prepared / "private", "btn")
    with session:
        other = session.create({"message": "A different publication"}, policy, group="messages")
        other.seal(purpose="delivery").write(prepared / "publications/greeting.tn")
    with pytest.raises(ValueError, match="publication_id"):
        example["read"](prepared, url=catalog.url, volume=VOLUME)


def test_changed_signed_bytes_fail_native_verification(example, prepared, catalog):
    path = prepared / "publications/greeting.tn"
    original = path.read_bytes()
    altered = original.replace(b"hello.message", b"hello.tampered")
    assert altered != original
    path.write_bytes(altered)
    with pytest.raises(tn.governed.VerificationError):
        example["read"](prepared, url=catalog.url, volume=VOLUME)


def test_catalog_location_and_publication_id_do_not_replace_decryption_keys(
    example, prepared, catalog, tmp_path,
):
    other = tmp_path / "other-reader"
    example["prepare"](other)
    (prepared / "private/keys/keystore.json").write_bytes(
        (other / "private/keys/keystore.json").read_bytes()
    )
    with pytest.raises(tn.governed.NotEntitled):
        example["read"](prepared, url=catalog.url, volume=VOLUME)


@pytest.mark.parametrize("absolute", [False, True])
def test_shared_reader_rejects_publication_names_outside_the_volume(example, prepared, absolute):
    original = prepared / "publications/greeting.tn"
    outside = prepared / "outside.tn"
    outside.write_bytes(original.read_bytes())
    expected_id = tn.GovernedObject.read(original).id
    filename = str(outside) if absolute else "../outside.tn"
    with pytest.raises(ValueError, match="filename|fixed"):
        example["read_publication"](original.parent, filename, expected_id)


def test_prepare_refuses_to_replace_an_existing_workspace(example, tmp_path):
    workspace = tmp_path / "existing"
    workspace.mkdir()
    retained = workspace / "retained.txt"
    retained.write_bytes(b"keep this workspace")
    with pytest.raises(FileExistsError):
        example["prepare"](workspace)
    assert retained.read_bytes() == b"keep this workspace"
    assert list(workspace.iterdir()) == [retained]


@pytest.mark.parametrize("url", [
    "ftp://127.0.0.1", "http://user:secret@127.0.0.1", "http://@127.0.0.1",
    "http://127.0.0.1?token=secret", "http://127.0.0.1#fragment",
    "http://127.0.0.1:invalid", "http://127.0.0.1/\nignored", "http:///missing-host",
])
def test_invalid_base_urls_are_refused_before_any_network_request(example, tmp_path, monkeypatch, url):
    def unexpected_network(*args, **kwargs):
        pytest.fail("invalid URL reached the network")

    monkeypatch.setattr("urllib.request.build_opener", unexpected_network)
    with pytest.raises(ValueError, match="base URL"):
        example["read"](tmp_path, url=url, volume=VOLUME)


def test_http_refusal_does_not_echo_token_from_server_error(example, prepared, catalog, monkeypatch):
    token = "secret-test-token"
    monkeypatch.setenv("TN_UNITY_TOKEN", token)
    catalog.state.update(status=403, reason=f"Denied {token}", body={"error": token})
    with pytest.raises(RuntimeError, match="HTTP 403") as failure:
        example["read"](prepared, url=catalog.url, volume=VOLUME)
    assert token not in "".join(traceback.format_exception(failure.value))


def test_redirect_is_refused_without_forwarding_credentials(example, prepared, catalog, monkeypatch):
    monkeypatch.setenv("TN_UNITY_TOKEN", "redirect-test-token")
    catalog.state.update(status=302, redirect=catalog.url + "/redirected")
    with pytest.raises(RuntimeError, match="HTTP 302"):
        example["read"](prepared, url=catalog.url, volume=VOLUME)
    assert len(catalog.state["requests"]) == 1


def test_invalid_token_is_refused_without_printing_it(example, prepared, catalog, monkeypatch):
    token = "secret\ninjected-header"
    monkeypatch.setenv("TN_UNITY_TOKEN", token)
    with pytest.raises(ValueError, match="TN_UNITY_TOKEN") as failure:
        example["read"](prepared, url=catalog.url, volume=VOLUME)
    assert "secret" not in "".join(traceback.format_exception(failure.value))
    assert catalog.state["requests"] == []
