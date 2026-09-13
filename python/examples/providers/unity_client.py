"""Read-only Unity volume lookup and pinned native publication loading."""
import json
import os
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request

import tn


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def lookup_volume(base_url: str, full_name: str) -> dict:
    """Fetch volume metadata using an optional TN_UNITY_TOKEN bearer token."""
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


def volume_directory(url: str, volume: str, expected_directory) -> Path:
    """Require the requested volume to name the exact expected local directory."""
    metadata = lookup_volume(url, volume)
    directory = Path(os.path.abspath(Path(expected_directory).expanduser()))
    if metadata.get("full_name") != volume:
        raise ValueError("Unity full_name does not match the requested volume")
    if metadata.get("storage_location") != directory.as_uri():
        raise ValueError("Unity storage_location does not match the expected publication directory")
    return directory


def read_publication(directory, filename: str, expected_id: str) -> tn.GovernedObject:
    """Read a fixed local file and require its native signature and expected identity."""
    if (filename in ("", ".", "..") or Path(filename).name != filename
            or "\\" in filename):
        raise ValueError("publication filename must be a single local filename")
    path = Path(directory).expanduser().absolute() / filename
    if path.resolve(strict=True) != path:
        raise ValueError("publication must remain at its fixed local path")
    publication = tn.GovernedObject.read(path)
    if publication.id != expected_id:
        raise ValueError("publication_id does not match the expected publication")
    return publication
