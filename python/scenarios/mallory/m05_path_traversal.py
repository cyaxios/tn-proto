"""Mallory m05 — path traversal + malformed filename rejection.

The vault accepts `PUT /projects/:id/files/:name`. A server that
blindly takes `:name` and writes it under `vault_blobs/<did>/<project>/<name>`
could be tricked into writing outside the project dir. Real vaults
validate `:name` or normalize it out. This scenario probes several
hostile filename shapes and confirms they're rejected (or at worst
rendered inert by URL encoding) rather than succeeding and placing
state in a dangerous location.
"""

from __future__ import annotations

import urllib.parse

from scenarios._harness import Scenario, ScenarioContext
from tn.identity import Identity
from tn.vault_client import VaultClient

EVIL_NAMES = [
    "..escape.txt",  # simple up-one
    "..%2Fescape.txt",  # URL-encoded slash (server may decode)
    "foo/../../bar.txt",  # embedded ..
    "a" * 256 + ".bin",  # overlong filename
    "with spaces.txt",  # whitespace (valid? may be accepted)
    "with\x00null.txt",  # embedded null
    ".hidden",  # dotfile
    "",  # empty (URL: .../files/)
]


class MalloryPathTraversal(Scenario):
    persona = "mallory"
    name = "m05_path_traversal"
    tags = {"vault", "security", "upload"}
    needs_vault = True

    def run(self, ctx: ScenarioContext) -> None:
        assert ctx.vault is not None
        base = ctx.vault.base_url

        ident = Identity.create_new()
        client = VaultClient.for_identity(ident, base)
        client.reset_account()

        proj = client.create_project("m05-project")
        project_id = proj.get("id") or proj.get("_id")
        ctx.record("project_id", project_id)

        statuses: dict[str, int] = {}
        succeeded: list[str] = []

        for raw in EVIL_NAMES:
            encoded = urllib.parse.quote(raw, safe="")
            url = f"{base}/api/v1/projects/{project_id}/files/{encoded}"
            resp = client._http.put(
                url,
                headers={
                    "Authorization": f"Bearer {client.token}",
                    "Content-Type": "application/octet-stream",
                },
                content=b"payload",
            )
            statuses[raw] = resp.status_code
            if 200 <= resp.status_code < 300:
                succeeded.append(raw)

        ctx.record("per_name_status", statuses)
        ctx.record("succeeded_names", succeeded)

        # Real-traversal names (contain path separator `/` that could
        # escape the per-project dir, or embedded NUL that breaks C
        # string parsing in the blob-dir code). A `..` prefix alone is
        # just a filename and isn't a traversal.
        real_escape_names = [n for n in EVIL_NAMES if "/" in n or "\x00" in n]
        # 405 is also a legitimate rejection — embedded slashes cause the
        # route pattern to not match, which returns "Method Not Allowed"
        # for the deeper-path URL. Functionally: the PUT didn't land.
        for name in real_escape_names:
            ctx.assert_invariant(
                f"rejected__{name!r}",
                statuses.get(name, 0) in (400, 404, 405, 422),
            )

        # Verify the blob dir has no real-escape artifacts in the listing.
        listing = client.list_files(project_id)
        server_names = {f.get("name") for f in listing}
        for name in real_escape_names:
            ctx.assert_invariant(
                f"not_in_listing__{name!r}",
                name not in server_names,
            )

        # Whole-scenario invariant: the set of successful uploads
        # contains NO real-escape name.
        ctx.assert_invariant(
            "no_real_escape_succeeded",
            not any(n in succeeded for n in real_escape_names),
        )

        client.close()
