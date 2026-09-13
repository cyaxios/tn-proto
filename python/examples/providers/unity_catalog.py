"""Read a pinned TN publication located by a Unity Catalog external volume.

Use a new workspace in private application storage. Register only its
publications directory with Unity; the private directory contains credentials.
This example performs a catalog GET and does not register or update volumes.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request

import tn


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from persistent_keys.configuration import configure
from persistent_keys.setup import provision


def prepare(workspace) -> str:
    """Provision BTN keys and a greeting once; return the public directory URI."""
    workspace = Path(workspace).expanduser().resolve()
    workspace.mkdir(mode=0o700, parents=True, exist_ok=False)
    private = workspace / "private"
    publications = workspace / "publications"
    provision(private, "btn")
    publications.mkdir()
    session, policy = configure(private, "btn")
    with session:
        data = session.create({"message": "Hello, world!"}, policy, group="messages")
        publication = data.seal(purpose="delivery")
        publication.write(publications / "greeting.tn")
        (private / "expected-publication.json").write_text(
            json.dumps({"publication_id": publication.id}, indent=2) + "\n",
            encoding="utf-8",
        )
    return publications.as_uri()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def _lookup_volume(base_url: str, full_name: str) -> dict:
    try:
        parsed = urllib.parse.urlsplit(base_url)
        port = parsed.port
        valid = (
            parsed.scheme in ("http", "https") and parsed.hostname
            and parsed.username is None and parsed.password is None
            and "?" not in base_url and "#" not in base_url
            and not any(char.isspace() or ord(char) < 32 for char in base_url)
            and (port is None or port > 0)
        )
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("base URL must be HTTP(S), with a host and no credentials, query or fragment")
    if len(full_name.split(".")) != 3 or any(not part for part in full_name.split(".")):
        raise ValueError("volume must be a full_name in catalog.schema.volume form")
    token = os.environ.get("TN_UNITY_TOKEN", "")
    if any(ord(char) < 32 or ord(char) == 127 for char in token):
        raise ValueError("TN_UNITY_TOKEN contains invalid control characters")
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    endpoint = (
        base_url.rstrip("/") + "/api/2.1/unity-catalog/volumes/"
        + urllib.parse.quote(full_name, safe="")
    )
    request = urllib.request.Request(endpoint, headers=headers, method="GET")
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=10) as response:
            metadata = json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"Unity lookup failed with HTTP {error.code}") from None
    if not isinstance(metadata, dict):
        raise ValueError("Unity volume response must be a JSON object")
    return metadata


def read(workspace, *, url: str, volume: str) -> str:
    """Validate the catalog location and signed identity, then open with stored keys."""
    workspace = Path(workspace).expanduser().resolve()
    private = workspace / "private"
    publications = workspace / "publications"
    metadata = _lookup_volume(url, volume)
    if metadata.get("full_name") != volume:
        raise ValueError("Unity full_name does not match the requested volume")
    if metadata.get("storage_location") != publications.as_uri():
        raise ValueError("Unity storage_location does not match this workspace's publications")
    path = publications / "greeting.tn"
    if path.resolve(strict=True) != path:
        raise ValueError("greeting.tn must remain at its fixed local publication path")
    publication = tn.GovernedObject.read(path)
    expected = json.loads((private / "expected-publication.json").read_text(encoding="utf-8"))
    if publication.id != expected["publication_id"]:
        raise ValueError("publication_id does not match the privately retained publication")
    session, _ = configure(private, "btn")
    with session:
        return session.unseal(publication, purpose="greeting").get("message")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("prepare", help="create a new private workspace and signed greeting")
    setup.add_argument("workspace", type=Path)
    receiving = commands.add_parser("read", help="locate the pinned greeting through a Unity volume")
    receiving.add_argument("workspace", type=Path)
    receiving.add_argument("--url", required=True)
    receiving.add_argument("--volume", required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        print(prepare(args.workspace))
    else:
        print(read(args.workspace, url=args.url, volume=args.volume))


if __name__ == "__main__":
    main()
