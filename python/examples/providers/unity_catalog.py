"""Read a pinned TN publication located by a Unity Catalog external volume.

Use a new workspace in private application storage. Register only its
publications directory with Unity; the private directory contains credentials.
This example performs a catalog GET and does not register or update volumes.
"""
import argparse
import json
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from persistent_keys.configuration import configure
from persistent_keys.setup import provision
from providers.unity_client import read_publication, volume_directory


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


def read(workspace, *, url: str, volume: str) -> str:
    """Validate the catalog location and signed identity, then open with stored keys."""
    workspace = Path(workspace).expanduser().resolve()
    private = workspace / "private"
    publications = volume_directory(url, volume, workspace / "publications")
    expected = json.loads((private / "expected-publication.json").read_text(encoding="utf-8"))
    publication = read_publication(publications, "greeting.tn", expected["publication_id"])
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
