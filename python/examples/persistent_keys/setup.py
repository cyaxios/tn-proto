"""Create one persistent example installation. Refuse to replace an existing one."""
import argparse
import json
from pathlib import Path
from tn.providers import FileKeyStore


def provision(directory, cipher):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    config = {"application": "hello-service", "cipher": cipher, "groups": ["messages"]}
    FileKeyStore.create(directory / "keys" / "keystore.json", config["application"], config["groups"], cipher=cipher)
    (directory / "config.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    (directory / "agents.md").write_text(Path(__file__).with_name("agents.md").read_text(encoding="utf-8"), encoding="utf-8")
    print(f"Created {cipher.upper()} configuration and persistent keys")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--cipher", required=True, choices=["btn", "jwe", "hibe"])
    args = parser.parse_args()
    provision(args.directory, args.cipher)
