"""TN command-line interface.

Top-level verbs (CI-shaped — every verb runs unattended, machine output,
no interactive prompts unless a TTY is detected):

    tn init <project>        One-time scaffold of identity + ceremony.
                             Generates a BIP-39 mnemonic; in a TTY it's
                             shown once on stdout, in CI / non-TTY it's
                             persisted into identity.json and a one-line
                             status is printed (treat identity.json as
                             a secret then). Creates <project>/tn.yaml
                             + <project>/.tn/tn/keys/ and writes
                             identity.json to $XDG_DATA_HOME/tn/.

    tn add_recipient         One-shot mint+bundle for a new recipient.
        <group> <did|label>  Friendly wrapper over tn.pkg.bundle_for_recipient
        [--out path]         (the explicit verb is `tn bundle`).

    tn bundle <did> <out>    Mint a kit_bundle .tnpkg for one recipient.
        [--groups a,b,c]     Defaults to every non-internal group.

    tn rotate [<group>]      The deploy primitive. Bumps each target
        [--groups a,b,c]     group's index_epoch via tn.admin.rotate,
        [--out path]         then emits one kit_bundle .tnpkg per
                             surviving recipient — the artifact CI
                             uploads (or the publisher hands off
                             directly) so recipients get the new keys.
                             No arg = rotate every non-internal group.
                             Vault-linked ceremonies push state to the
                             vault as a side effect (autosync hook).

    tn absorb <package>      Install a .tnpkg into the ceremony already
                             active here (run from a project dir or pass
                             --yaml). It does NOT create a ceremony; to
                             start one from a downloaded seed, use
                             `tn import`.

    tn import <package>      Bootstrap a ceremony from a downloaded
                             project_seed .tnpkg: writes tn.yaml + the
                             keystore into the current directory and binds
                             the runtime. The "carry a seed to a new
                             device" entry point.

    tn export --kind         Mint a project_seed .tnpkg (tn.yaml + raw
        project_seed         keystore) from the active ceremony to carry
        --include-secrets    to another device, where `tn import` restores
        --out <path>         it.

    tn read [<log>]          Print a log in flat decoded form.

    tn streams ...           Multi-ceremony stream listing / validation.
    tn validate ...          Schema / catalog validation helpers.
    tn show ...              Reflective inspection (env, config, etc.).

    tn wallet ...            Subcommands for an already-scaffolded identity:
        link <yaml>          Create a vault project + flip ceremony to
                             mode=linked + initial sealed upload.
        unlink <yaml>        Flip back to mode=local (vault data untouched).
        sync <yaml>          Force-push current ceremony state to vault.
        status [<yaml>]      Summary: DID, linked vault, ceremony state.
        pull-prefs           Refresh cached account prefs from vault.
        restore              Pull identity + ceremonies down on a fresh
                             machine (--mnemonic "...").
        export-mnemonic      Re-display the current identity's mnemonic
                             (requires mnemonic-sealed storage or ABORTS
                             if identity.json doesn't keep it).

Python module entry point: `python -m tn.cli [verb] ...`
Installed console script: `tn [verb] ...`
"""

from __future__ import annotations

import argparse
import sys

from .cli_admin import (
    cmd_admin_add_recipient,
    cmd_admin_revoke_recipient,
    cmd_admin_revoked_count,
    cmd_admin_rotate,
)
from .cli_auth import (
    cmd_account_connect,
    cmd_auth_connect,
    cmd_auth_login,
    cmd_auth_logout,
    cmd_auth_status,
    cmd_auth_use,
    cmd_auth_whoami,
)
from .cli_canonical import cmd_canonical
from .cli_compile import cmd_compile
from .cli_firehose import _firehose_enabled, _register_firehose_subcommands
from .cli_info import cmd_info
from .cli_init import cmd_init
from .cli_introspect import cmd_streams, cmd_validate
from .cli_invite import add_invite_parser
from .cli_pkg import (
    cmd_absorb,
    cmd_add_recipient,
    cmd_bundle,
    cmd_export,
    cmd_group_add,
    cmd_import,
    cmd_rotate,
)
from .cli_read import cmd_read
from .cli_seal import cmd_seal
from .cli_show import cmd_show, cmd_show_env, cmd_show_profiles
from .cli_vault import cmd_vault_link, cmd_vault_unlink
from .cli_verify import cmd_verify
from .cli_wallet import (
    cmd_wallet_export_mnemonic,
    cmd_wallet_link,
    cmd_wallet_pull_prefs,
    cmd_wallet_restore,
    cmd_wallet_status,
    cmd_wallet_sync,
    cmd_wallet_unlink,
    cmd_wallet_watch,
)

# ---------------------------------------------------------------------
# argparse wiring
# ---------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tn",
        description="TN protocol CLI — identity + ceremony + vault wallet.",
    )
    sub = p.add_subparsers(dest="verb", required=True)

    # --- tn init -------------------------------------------------
    p_init = sub.add_parser("init", help="Scaffold identity + ceremony.")
    p_init.add_argument(
        "project",
        nargs="?",
        default=None,
        help=(
            "Project name. The ceremony is created at ./.tn/<project>/. "
            "If a path is passed, only the basename is used. Omit to use "
            "the current folder's name."
        ),
    )
    # ``--version-name`` stamps a per-instance nickname inside the vault
    # project (e.g. 'laptop-dev', 'ci', 'prod'). Defaults to <project>.
    # The legacy --project-name flag was dropped (0.5.0a2): the positional
    # IS the project name; there is no separate vault-side label to
    # specify. Operators who want a different vault label later can
    # rename via a future `tn wallet relabel` verb.
    p_init.add_argument(
        "--version-name",
        default=None,
        help=(
            "Per-instance nickname inside the project (e.g. "
            "'laptop-dev', 'ci', 'prod'). Defaults to <project>."
        ),
    )
    # ``btn`` is the shipping default cipher; ``jwe`` is the pure-Python
    # RFC 7516 alternative; ``hibe`` is the identity-path (BBG) cipher.
    p_init.add_argument("--cipher", default="btn", choices=["btn", "jwe", "hibe"])
    p_init.add_argument("--words", type=int, default=12, choices=[12, 15, 18, 21, 24])
    p_init.add_argument(
        "--mnemonic-file", default=None, help="Read mnemonic from this file (non-interactive)."
    )
    p_init.add_argument(
        "--link",
        default=None,
        help=(
            "Vault URL to link this ceremony to. Defaults to identity.linked_vault, "
            "then $TN_VAULT_URL, then https://vault.tn-proto.org."
        ),
    )
    p_init.add_argument(
        "--no-link",
        action="store_true",
        help="Skip auto-link + initial backup. Produces an offline-only ceremony.",
    )
    p_init.add_argument(
        "--force", action="store_true", help="Overwrite existing project directory."
    )
    p_init.add_argument(
        "--skip-confirm", action="store_true", help="Do not pause for Enter after showing mnemonic."
    )
    p_init.add_argument(
        "--keep-mnemonic",
        action="store_true",
        help=(
            "Persist the recovery phrase into identity.json "
            "so `tn wallet export-mnemonic` can re-display it "
            "later. Trades some filesystem blast radius for "
            "recovery convenience."
        ),
    )
    p_init.add_argument(
        "--no-cache-key", dest="cache_key", action="store_false", default=None,
        help="Skip caching the Account Wrapping Key (AWK) locally.")
    p_init.set_defaults(func=cmd_init)

    # --- tn wallet ---------------------------------------------
    p_wallet = sub.add_parser("wallet", help="Wallet/vault operations.")
    wsub = p_wallet.add_subparsers(dest="wverb", required=True)

    p_status = wsub.add_parser("status")
    p_status.add_argument(
        "yaml", nargs="?", default=None, help="Optional ceremony yaml to describe."
    )
    p_status.set_defaults(func=cmd_wallet_status)

    # 0.4.2a9: wallet link / unlink / sync all default to the
    # discovered yaml the same way `tn read` and `tn status` do —
    # operator doesn't have to type the full path when one is in
    # scope. Pass an explicit yaml only when you want to override
    # discovery.
    p_link = wsub.add_parser("link")
    p_link.add_argument(
        "yaml", nargs="?", default=None,
        help="Optional ceremony yaml. Default: discover via the standard chain.",
    )
    p_link.add_argument("--vault", default=None)
    p_link.set_defaults(func=cmd_wallet_link)

    p_unlink = wsub.add_parser("unlink")
    p_unlink.add_argument(
        "yaml", nargs="?", default=None,
        help="Optional ceremony yaml. Default: discover via the standard chain.",
    )
    p_unlink.set_defaults(func=cmd_wallet_unlink)

    p_sync = wsub.add_parser("sync")
    p_sync.add_argument(
        "yaml", nargs="?", default=None,
        help="Optional ceremony yaml. Default: discover via the standard chain.",
    )
    p_sync.add_argument(
        "--drain-queue",
        action="store_true",
        help="Retry any pending autosync failures; clear queue on success.",
    )
    p_sync.add_argument(
        "--pull",
        action="store_true",
        help=(
            "Stage the vault's account inbox into the local inbox dir "
            "WITHOUT absorbing (back-compat escape hatch). Requires "
            "`tn account connect`. Run `tn absorb <path>` on each staged "
            "file. Bare `tn wallet sync` now pulls+absorbs+pushes for you."
        ),
    )
    p_sync.add_argument(
        "--push-only",
        action="store_true",
        help=(
            "Skip the pull/absorb (merge) step and only upload this "
            "ceremony's backup to the vault — the pre-two-way behavior."
        ),
    )
    p_sync.add_argument(
        "--account-passphrase", "--passphrase",
        dest="passphrase",
        default=None,
        help=(
            "Account recovery passphrase - derives the backup key (AWK) that "
            "wraps the project BEK for the whole-body push. Falls back to "
            "TN_ACCOUNT_PASSPHRASE. (--passphrase is a deprecated alias.)"
        ),
    )
    p_sync.set_defaults(func=cmd_wallet_sync)

    p_watch = wsub.add_parser("watch", help="Periodic unattended sync loop.")
    p_watch.add_argument(
        "yaml", nargs="?", default=None,
        help="Optional ceremony yaml. Default: discover via standard chain.",
    )
    p_watch.add_argument("--vault", default=None)
    p_watch.set_defaults(func=cmd_wallet_watch)

    p_pull = wsub.add_parser("pull-prefs")
    p_pull.add_argument("--vault", default=None)
    p_pull.set_defaults(func=cmd_wallet_pull_prefs)

    p_restore = wsub.add_parser("restore")
    # Legacy mnemonic flow.
    p_restore.add_argument("--mnemonic", default=None, help="Recovery phrase as a quoted string.")
    p_restore.add_argument("--mnemonic-file", default=None)
    p_restore.add_argument("--vault", default=None, help="Vault URL to pull ceremonies from.")
    p_restore.add_argument(
        "--project-ids", default=None, help="Comma-separated list of project ids."
    )
    p_restore.add_argument("--all-projects", action="store_true")
    p_restore.add_argument(
        "out_dir",
        nargs="?",
        default=None,
        help=(
            "Output directory for the restored ceremony. Required for the "
            "new account-bound flow; optional for the legacy mnemonic flow."
        ),
    )
    # Backward compat: --out-dir was the previous spelling. Keep it as
    # an alias that overrides the positional.
    p_restore.add_argument("--out-dir", dest="out_dir_flag", default=None)
    p_restore.add_argument("--force", action="store_true")
    # Account-bound restore flow knobs.
    p_restore.add_argument(
        "--passphrase",
        action="store_true",
        help="Use passphrase fallback instead of opening a browser.",
    )
    p_restore.add_argument(
        "--port",
        type=int,
        default=None,
        help="Pin the loopback port (default: kernel-allocated).",
    )
    p_restore.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Loopback wait timeout in seconds (default: 300).",
    )
    p_restore.add_argument(
        "--credential-id",
        default=None,
        help="For --passphrase: which credential row's KDF to derive against.",
    )
    p_restore.add_argument(
        "--project-id",
        default=None,
        help="For --passphrase: project id to restore (skips interactive pick).",
    )
    p_restore.add_argument(
        "--session-token",
        "--jwt",  # legacy alias
        dest="session_token",
        default=None,
        help="For --passphrase: vault session token (no browser handoff in this mode).",
    )
    p_restore.set_defaults(func=cmd_wallet_restore)

    p_export = wsub.add_parser("export-mnemonic")
    p_export.add_argument(
        "--yes", action="store_true", help="Confirm you want to display the phrase on screen."
    )
    p_export.set_defaults(func=cmd_wallet_export_mnemonic)

    # --- tn account -------------------------------------------------
    # Connect-code redemption: bind THIS device's DID to an existing
    # OAuth vault account so subsequent /account/* routes accept this
    # DID's challenge-issued JWT. The CLI counterpart to the dashboard's
    # "Connect a new app or device" action.
    p_account = sub.add_parser(
        "account",
        help="Vault account binding (legacy - prefer `tn auth`).",
    )
    asub = p_account.add_subparsers(dest="averb", required=True)

    p_connect = asub.add_parser(
        "connect",
        help="Legacy alias of `tn auth connect`: redeem a tn_connect_<...> code.",
    )
    p_connect.add_argument(
        "code",
        help="The single-use connect code copied from the vault dashboard.",
    )
    p_connect.add_argument(
        "--yaml", default=None,
        help="Path to your tn.yaml. Default: discover via the standard chain.",
    )
    p_connect.add_argument(
        "--vault", default=None,
        help="Vault URL. Default: identity.linked_vault, then $TN_VAULT_URL, then the hosted vault.",
    )
    p_connect.add_argument(
        "--identity", default=None,
        help=(
            "Tier-2 override: explicit identity.json to sign the redeem with. "
            "Default cascade: machine-global identity, then the ceremony keystore key."
        ),
    )
    p_connect.add_argument(
        "--account-passphrase", "--passphrase",
        dest="passphrase", default=None,
        help=(
            "Account recovery passphrase, presented ONCE to cache the backup "
            "key (AWK) so a later `tn init` backs up unattended. Only the "
            "derived key is stored, never the passphrase. (--passphrase is a "
            "deprecated alias.)"
        ),
    )
    p_connect.set_defaults(func=cmd_account_connect)

    # --- tn auth (canonical account/session surface) ----------------
    p_auth = sub.add_parser(
        "auth", help="Account login / status / logout (the canonical surface)."
    )
    authsub = p_auth.add_subparsers(dest="authverb", required=True)

    p_auth_status = authsub.add_parser(
        "status",
        help="Show account, vault, device, and backup state (vault-verified).",
    )
    p_auth_status.add_argument(
        "--vault", default=None,
        help="Vault URL. Default: identity.linked_vault > $TN_VAULT_URL > hosted.",
    )
    p_auth_status.set_defaults(func=cmd_auth_status)

    p_auth_login = authsub.add_parser(
        "login",
        help="Sign in, enroll this device, and cache the backup key.",
    )
    p_auth_login.add_argument("--vault", default=None, help="Vault URL override.")
    p_auth_login.add_argument(
        "--code", default=None,
        help="Headless: redeem a tn_connect_<code> to enroll (no browser).",
    )
    p_auth_login.add_argument(
        "--account-passphrase", dest="account_passphrase", default=None,
        help="Cache the backup key from the account recovery passphrase "
             "(or set TN_ACCOUNT_PASSPHRASE).",
    )
    p_auth_login.add_argument(
        "--no-cache-key", dest="cache_key", action="store_false", default=None,
        help="Skip caching the Account Wrapping Key (AWK) locally.")
    p_auth_login.set_defaults(func=cmd_auth_login)

    p_auth_logout = authsub.add_parser(
        "logout",
        help="Sign this machine out: clear the cached backup key + account link.",
    )
    p_auth_logout.set_defaults(func=cmd_auth_logout)

    p_auth_whoami = authsub.add_parser(
        "whoami", help="One line: this device, its account, and its vault."
    )
    p_auth_whoami.set_defaults(func=cmd_auth_whoami)

    p_auth_use = authsub.add_parser(
        "use", help="Point this machine at a vault (writes linked_vault)."
    )
    p_auth_use.add_argument(
        "vault", help="Vault base URL, e.g. https://vault.tn-proto.org"
    )
    p_auth_use.set_defaults(func=cmd_auth_use)

    p_auth_connect = authsub.add_parser(
        "connect",
        help="Enroll this device via a connect code (canonical home for "
             "`tn account connect`).",
    )
    p_auth_connect.add_argument(
        "code", help="The tn_connect_<...> code minted in the dashboard."
    )
    p_auth_connect.add_argument("--vault", default=None)
    p_auth_connect.add_argument(
        "--account-passphrase", dest="account_passphrase", default=None,
        help="Also cache the backup key (or set TN_ACCOUNT_PASSPHRASE).",
    )
    p_auth_connect.set_defaults(func=cmd_auth_connect)

    # --- tn bundle [--yaml=...] <recipient_did> <out> -----------
    p_bundle = sub.add_parser(
        "bundle",
        help="Mint a kit_bundle .tnpkg for one recipient (FINDINGS #5 footgun-free).",
    )
    p_bundle.add_argument("recipient", help="DID of the recipient receiving the kit.")
    p_bundle.add_argument("out", help="Destination .tnpkg path.")
    p_bundle.add_argument(
        "--yaml", default=None,
        help="Path to your tn.yaml. Default: discover via $TN_YAML / ./tn.yaml / ~/.tn/tn.yaml.",
    )
    p_bundle.add_argument(
        "--groups",
        default=None,
        help="Comma-separated group names. Default: every non-tn.agents group in the ceremony.",
    )
    p_bundle.add_argument(
        "--seal-for-recipient",
        action="store_true",
        default=False,
        help="Wrap the bundle body under a per-export key only the named "
             "recipient DID can unwrap. Lets a CDN or vault host the file "
             "without being able to read its contents.",
    )
    p_bundle.set_defaults(func=cmd_bundle)

    # --- tn add_recipient <group> <did-or-label> -------------
    # The friendlier alias the cash-_register assignment expected
    # (FINDINGS S6.4): yaml auto-discovered, output path defaults to
    # ./<label>.tnpkg, and a bare label gets a synthetic placeholder
    # DID for the attestation event.
    p_add = sub.add_parser(
        "add_recipient",
        help="One-shot mint+bundle: `tn add_recipient <group> <did-or-label>`.",
    )
    p_add.add_argument("group", help="Group name to mint a kit for (e.g. default).")
    p_add.add_argument(
        "recipient",
        help="Recipient DID, or a friendly label (auto-prefixed with did:key:zLabel-).",
    )
    p_add.add_argument(
        "--out", default=None,
        help="Output .tnpkg path. Default: ./<label>.tnpkg in the cwd.",
    )
    p_add.add_argument(
        "--yaml", default=None,
        help="Path to your tn.yaml. Default: discover via $TN_YAML / ./tn.yaml / ~/.tn/tn.yaml.",
    )
    p_add.add_argument(
        "--seal-for-recipient",
        action="store_true",
        default=False,
        help="Wrap the bundle body under a per-export key only the named "
             "recipient DID can unwrap. Lets a CDN or vault host the file "
             "without being able to read its contents.",
    )
    p_add.set_defaults(func=cmd_add_recipient)

    # --- tn invite <recipient> <out.zip> -----------------------
    # CLI-side invite-mint: mints the inner kit (via the same
    # admin.add_recipient(..., raw=True) the server uses) and wraps it in a
    # tn-invite-<id>.zip with a manifest.json — the wrapper that previously
    # only tn_proto_web produced. Enables a same-language mint -> inbox
    # accept round-trip inside tn_proto. See cli_invite.py.
    add_invite_parser(sub)

    # --- tn group add <name> -----------------------------------
    # Group-add was API-only (tn.ensure_group); this verb exposes it on
    # the CLI. Under the multi-ceremony layout the group lands in the
    # authoritative project-root yaml, so it survives for fresh-process
    # readers and a subsequent `tn add_recipient`.
    p_group = sub.add_parser(
        "group",
        help="Group management for an existing ceremony.",
    )
    g_sub = p_group.add_subparsers(dest="group_verb", required=True)
    p_group_add = g_sub.add_parser(
        "add",
        help="Add a group post-init: `tn group add <name> [--fields a,b]`.",
    )
    p_group_add.add_argument("name", help="Group name to add (e.g. partners).")
    p_group_add.add_argument(
        "--fields", default=None,
        help="Comma-separated field names to route into this group.",
    )
    p_group_add.add_argument(
        "--cipher", default=None, choices=["btn", "jwe", "hibe"],
        help="Cipher for the new group. Default: the ceremony's cipher.",
    )
    p_group_add.add_argument(
        "--yaml", default=None,
        help="Path to your tn.yaml. Default: discover via $TN_YAML / ./tn.yaml / ~/.tn/tn.yaml.",
    )
    p_group_add.set_defaults(func=cmd_group_add)

    # --- tn admin <sub> ----------------------------------------
    # Low-level ceremony admin sub-dispatcher mirroring the TS `tn admin`
    # verb group (ts-sdk/src/cli/admin.ts). Machine-shaped: each
    # subcommand prints one JSON line and reuses the same tn.admin.*
    # functions the top-level `tn add_recipient` / `tn rotate` verbs use,
    # so `tn admin rotate` and `tn rotate` drive an identical rotation.
    # `admin revoke-recipient` is the new capability — Python had no CLI
    # path to revoke a recipient before this.
    p_admin = sub.add_parser(
        "admin",
        help="Low-level ceremony admin (add/revoke recipient, revoked-count, rotate).",
    )
    admin_sub = p_admin.add_subparsers(dest="admin_verb", required=True)

    p_admin_add = admin_sub.add_parser(
        "add-recipient",
        help="Register a recipient and mint their kit: "
             "`tn admin add-recipient --group <g> --out <kit> [--recipient-did <did>]`.",
    )
    p_admin_add.add_argument("--group", default="default", help="Target group (default: default).")
    p_admin_add.add_argument(
        "--out", default=None,
        help="Kit output path (required). `.tnpkg` mints an absorbable bundle; "
             "`<group>.btn.mykit` mints a raw kit.",
    )
    p_admin_add.add_argument(
        "--recipient-did", dest="recipient_did", default=None,
        help="Recipient DID recorded on the tn.recipient.added attestation.",
    )
    p_admin_add.add_argument(
        "--yaml", default=None,
        help="Path to your tn.yaml. Default: discover via the standard chain.",
    )
    p_admin_add.set_defaults(func=cmd_admin_add_recipient)

    p_admin_revoke = admin_sub.add_parser(
        "revoke-recipient",
        help="Revoke a recipient: "
             "`tn admin revoke-recipient --group <g> --leaf <i> [--recipient-did <did>]`.",
    )
    p_admin_revoke.add_argument("--group", default="default", help="Target group (default: default).")
    p_admin_revoke.add_argument(
        "--leaf", type=int, default=None,
        help="btn leaf index to revoke (required for btn unless --recipient-did is given).",
    )
    p_admin_revoke.add_argument(
        "--recipient-did", dest="recipient_did", default=None,
        help="Revoke by DID (btn resolves it to the active leaf; JWE uses it directly).",
    )
    p_admin_revoke.add_argument(
        "--yaml", default=None,
        help="Path to your tn.yaml. Default: discover via the standard chain.",
    )
    p_admin_revoke.set_defaults(func=cmd_admin_revoke_recipient)

    p_admin_count = admin_sub.add_parser(
        "revoked-count",
        help="Print the number of revoked recipients in a btn group: "
             "`tn admin revoked-count --group <g>`.",
    )
    p_admin_count.add_argument("--group", default="default", help="Target group (default: default).")
    p_admin_count.add_argument(
        "--yaml", default=None,
        help="Path to your tn.yaml. Default: discover via the standard chain.",
    )
    p_admin_count.set_defaults(func=cmd_admin_revoked_count)

    p_admin_rotate = admin_sub.add_parser(
        "rotate",
        help="Rotate group keys and emit per-recipient .tnpkg artifacts (JSON output): "
             "`tn admin rotate [--group <g> | --groups a,b] [--out <dir|.tnpkg>]`.",
    )
    # rotate defaults --group to None (vs "default" above) so the shared
    # _rotate_select_groups helper expands to every non-internal group
    # when neither --group nor --groups is passed — matching TS + `tn rotate`.
    p_admin_rotate.add_argument(
        "--group", default=None,
        help="Single group to rotate. Omit (and skip --groups) to rotate "
             "every non-internal group. Mutually exclusive with --groups.",
    )
    p_admin_rotate.add_argument(
        "--groups", default=None,
        help="Comma-separated subset of groups. Mutually exclusive with --group.",
    )
    p_admin_rotate.add_argument(
        "--out", default=None,
        help="Where to write per-recipient .tnpkg artifacts. A directory "
             "(default: ./rotated_<UTC_TS>/) writes one per recipient; a "
             ".tnpkg path writes a single file (single-recipient rotations only).",
    )
    p_admin_rotate.add_argument(
        "--yaml", default=None,
        help="Path to your tn.yaml. Default: discover via the standard chain.",
    )
    p_admin_rotate.set_defaults(func=cmd_admin_rotate)

    # --- tn absorb <package> -----------------------------------
    p_absorb = sub.add_parser(
        "absorb",
        help=(
            "Absorb a .tnpkg (kit bundle, enrolment, etc.) into the ceremony "
            "already active here. It does not create a ceremony; to start one "
            "from a downloaded seed, use `tn import` instead."
        ),
    )
    p_absorb.add_argument("package", help="Path to the .tnpkg to absorb.")
    p_absorb.add_argument(
        "--yaml", default=None,
        help="Path to the absorber's tn.yaml. Default: discover via the standard chain.",
    )
    p_absorb.add_argument(
        "--allow-self-absorb", action="store_true",
        help=(
            "Allow absorbing a .tnpkg this ceremony itself minted. The "
            "default is to refuse: self-absorb overwrites the publisher's "
            "own keystore with a reader-kit copy, which is almost never "
            "what you want outside test/recovery flows."
        ),
    )
    p_absorb.set_defaults(func=cmd_absorb)

    # --- tn import <package> (user-facing restore verb) ---------
    p_import = sub.add_parser(
        "import",
        help="Restore a project_seed backup (keys + config) into this directory.",
    )
    p_import.add_argument("package", help="Path to the .tnpkg backup to restore.")
    p_import.set_defaults(func=cmd_import)

    # --- tn export --kind project_seed --out <file> --include-secrets
    p_export_pkg = sub.add_parser(
        "export",
        help="Mint a .tnpkg backup (--kind project_seed) from the active ceremony.",
    )
    p_export_pkg.add_argument(
        "--kind", default="project_seed", choices=["project_seed"],
        help="Bundle kind to mint. Default: project_seed.",
    )
    p_export_pkg.add_argument(
        "--out", required=True, help="Destination .tnpkg path.",
    )
    p_export_pkg.add_argument(
        "--include-secrets", action="store_true",
        help="Required for project_seed: acknowledges the bundle carries raw private keys.",
    )
    p_export_pkg.add_argument(
        "--yaml", default=None,
        help="Path to your tn.yaml. Default: discover via the standard chain.",
    )
    p_export_pkg.set_defaults(func=cmd_export)

    # --- tn rotate [<group>] [--groups a,b,c] [--out path] -----
    # The deploy-shaped verb: rotate one or more groups and emit
    # per-recipient kit_bundle .tnpkg artifacts so CI can upload them.
    # See cmd_rotate docstring for output shape and vault interaction.
    p_rotate = sub.add_parser(
        "rotate",
        help="Rotate group keys and emit per-recipient .tnpkg artifacts.",
    )
    p_rotate.add_argument(
        "group",
        nargs="?",
        default=None,
        help=(
            "Group to rotate. Omit (and skip --groups) to rotate every "
            "non-internal group in the ceremony — the default deploy shape."
        ),
    )
    p_rotate.add_argument(
        "--groups",
        default=None,
        help=(
            "Comma-separated subset of groups to rotate. Mutually "
            "exclusive with the positional <group>."
        ),
    )
    p_rotate.add_argument(
        "--out",
        default=None,
        help=(
            "Where to write the per-recipient .tnpkg artifacts. "
            "A directory (default: ./rotated_<UTC_TS>/) writes one .tnpkg "
            "per surviving recipient. A path ending in .tnpkg writes a "
            "single file (single-recipient rotations only)."
        ),
    )
    p_rotate.add_argument(
        "--yaml", default=None,
        help="Path to your tn.yaml. Default: discover via the standard chain.",
    )
    p_rotate.set_defaults(func=cmd_rotate)

    # --- tn read [<log>] ---------------------------------------
    p_read = sub.add_parser(
        "read",
        help="Print a log in flat, decrypted form (auto-routes cross-publisher).",
    )
    p_read.add_argument(
        "log",
        nargs="?",
        default=None,
        help="Optional log path (default: ceremony's main log). "
             "Cross-publisher logs are auto-routed via read_as_recipient (FINDINGS S6.2).",
    )
    p_read.add_argument(
        "--yaml", default=None,
        help="Path to your tn.yaml. Default: discover via the standard chain.",
    )
    # Read defaults to "everything on disk". A boolean-optional flag lets
    # callers narrow back to the current process run via `--no-all-runs`.
    p_read.add_argument(
        "--all-runs",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Include entries from previous runs (default: True). "
             "Pass `--no-all-runs` to restrict to this process run.",
    )
    read_security = p_read.add_mutually_exclusive_group()
    read_security.add_argument(
        "--verify",
        nargs="?",
        const="raise",
        choices=("raise", "skip"),
        default=None,
        help=(
            "Explicit verification handling: bare --verify means raise; "
            "--verify skip drops rejected rows with observability."
        ),
    )
    read_security.add_argument(
        "--no-verify",
        dest="verify",
        action="store_const",
        const=False,
        help="Explicitly disable integrity/authentication/authorization gates.",
    )
    p_read.set_defaults(func=cmd_read)

    # --- tn show env ------------------------------------------------
    # Reflective inventory of every TN_* env var the install reads or
    # would meaningfully accept. ``tn show env`` reflects the canonical
    # set the runtime recognizes. Three formats:
    #   human (default) — pretty table, secrets redacted
    #   env             — bash-style ``TN_FOO=value`` block, paste-able
    #   json            — programmatic / LLM consumption
    # --- tn streams --------------------------------------------
    # List ceremonies (streams) declared on disk under .tn/. Cheap
    # introspection for operators auditing what got registered as
    # code ran. Matches the multi-ceremony directory contract under .tn/.
    p_streams = sub.add_parser(
        "streams",
        help="List ceremonies/streams under .tn/ for the project.",
    )
    p_streams.add_argument(
        "--project-dir",
        default=None,
        help="Project root containing .tn/. Default: current directory.",
    )
    p_streams.add_argument(
        "--format",
        default="human",
        choices=["human", "json"],
        help="Output format. ``human`` is a table; ``json`` is a list "
             "of {name, profile, yaml_path} objects.",
    )
    p_streams.set_defaults(func=cmd_streams)

    # --- tn validate -------------------------------------------
    # Static check of the project's .tn/ tree: profile names valid,
    # yamls parseable, identity declared at default. Read-only;
    # exits non-zero on failure. Suitable as a pre-commit / CI step.
    p_validate = sub.add_parser(
        "validate",
        help="Validate the project's .tn/ configuration tree.",
    )
    p_validate.add_argument(
        "--project-dir",
        default=None,
        help="Project root containing .tn/. Default: current directory.",
    )
    p_validate.set_defaults(func=cmd_validate)

    p_show = sub.add_parser("show", help="Reflective inspection commands.")
    # DX review #21: ``required=False`` so ``tn show`` with no subverb
    # dispatches to a useful default (env) rather than spitting an
    # argparse usage error.
    show_sub = p_show.add_subparsers(dest="show_verb", required=False)
    p_show.set_defaults(func=cmd_show, format="human")
    p_show_env = show_sub.add_parser(
        "env",
        help="Print the canonical TN_* env-var surface (human / env / json).",
    )
    p_show_env.add_argument(
        "--format",
        default="human",
        choices=["human", "env", "json"],
        help="human (default) for the pretty table; env for a paste-able "
             "TN_FOO=value block (secrets present); json for programmatic use.",
    )
    p_show_env.set_defaults(func=cmd_show_env)

    # DX review #22: profile-catalog reflection.
    p_show_profiles = show_sub.add_parser(
        "profiles",
        help="Print the profile catalog (transaction / audit / secure_log / telemetry / stdout) with their encrypts/signs/chains/flush/sink matrices and intended-use blurbs.",
    )
    p_show_profiles.add_argument(
        "--format",
        default="human",
        choices=["human", "json"],
        help="human (default) for the pretty table + descriptions; json for programmatic use.",
    )
    p_show_profiles.set_defaults(func=cmd_show_profiles)

    # --- tn seal -----------------------------------------------
    # Public-only attest path: reads seal-input JSON line(s) from stdin,
    # emits envelope ndjson to stdout. No flags (pure stdin->stdout
    # contract; see cli_seal.cmd_seal).
    p_seal = sub.add_parser(
        "seal",
        help="Attest one envelope per stdin JSON line (public-only; emits ndjson).",
    )
    p_seal.set_defaults(func=cmd_seal)

    # --- tn verify ---------------------------------------------
    # Public-only verify path: reads envelope ndjson from stdin, writes
    # one {"ok": ...} result line per input. No flags.
    p_verify = sub.add_parser(
        "verify",
        help="Verify envelope ndjson read from stdin (public-only; one result line per input).",
    )
    p_verify.set_defaults(func=cmd_verify)

    # --- tn canonical ------------------------------------------
    # Diagnostic: echo the TN canonical bytes of each stdin JSON line.
    # No flags.
    p_canonical = sub.add_parser(
        "canonical",
        help="Echo the canonical UTF-8 bytes of each stdin JSON line (row_hash parity).",
    )
    p_canonical.set_defaults(func=cmd_canonical)

    # --- tn info -----------------------------------------------
    # Emit ONE attested entry from the CLI. Mirrors the TS `tn-js info`
    # flag surface: --yaml / --event / --level / repeatable --field k=v
    # (lands as args.field list; see cli_info.cmd_info).
    p_info = sub.add_parser(
        "info",
        help="Emit one attested log entry: `tn info --yaml <path> --event <type> [--field k=v]...`.",
    )
    p_info.add_argument(
        "--yaml", default=None, help="Path to the ceremony tn.yaml (required)."
    )
    p_info.add_argument(
        "--event", default=None, help="Event type to emit (required)."
    )
    p_info.add_argument(
        "--level", default="info",
        help="Log level. The four standard levels route to tn.<level>; "
             "any other string flows through tn.log verbatim. Default: info.",
    )
    p_info.add_argument(
        "--field", action="append", default=None,
        help="k=v field to carry on the entry. Repeatable.",
    )
    p_info.set_defaults(func=cmd_info)

    # --- tn compile --------------------------------------------
    # Package a keystore's btn reader kits into a .tnpkg. Mirrors the TS
    # `tn-js compile` flag surface: --keystore / --out / repeatable
    # --kit / --label / --full (see cli_compile.cmd_compile).
    p_compile = sub.add_parser(
        "compile",
        help="Compile keystore reader kits into a .tnpkg: "
             "`tn compile --keystore <dir> --out <file.tnpkg> [--kit <group>]...`.",
    )
    p_compile.add_argument(
        "--keystore", default=None, help="Keystore directory holding *.btn.mykit files (required)."
    )
    p_compile.add_argument(
        "--out", default=None, help="Destination .tnpkg path (required)."
    )
    p_compile.add_argument(
        "--kit", action="append", default=None,
        help="Group name to include. Repeatable. Default: every group.",
    )
    p_compile.add_argument(
        "--label", default=None,
        help="Human-readable label persisted into the manifest (state.label).",
    )
    p_compile.add_argument(
        "--full", action="store_true", default=False,
        help="Bundle private key material too (full_keystore kind).",
    )
    p_compile.set_defaults(func=cmd_compile)

    # --- tn vault link / unlink --------------------------------
    # Emit the attested tn.vault.linked / tn.vault.unlinked events to the
    # ceremony admin log (NOT vault-project creation; that's `tn wallet
    # link`). Positionals vault_did + project_id; --reason on unlink;
    # --yaml on both (see cli_vault.cmd_vault_link / cmd_vault_unlink).
    p_vault = sub.add_parser(
        "vault",
        help="Emit attested vault.link / vault.unlink events to the admin log.",
    )
    vsub = p_vault.add_subparsers(dest="vverb", required=True)

    p_vault_link = vsub.add_parser(
        "link",
        help="Emit tn.vault.linked: `tn vault link <vault-did> <project-id> [--yaml <path>]`.",
    )
    p_vault_link.add_argument("vault_did", help="DID of the vault being linked.")
    p_vault_link.add_argument("project_id", help="Project id linked at the vault.")
    p_vault_link.add_argument(
        "--yaml", default=None,
        help="Path to your tn.yaml. Default: discover via the standard chain.",
    )
    p_vault_link.set_defaults(func=cmd_vault_link)

    p_vault_unlink = vsub.add_parser(
        "unlink",
        help="Emit tn.vault.unlinked: `tn vault unlink <vault-did> <project-id> [--reason <r>] [--yaml <path>]`.",
    )
    p_vault_unlink.add_argument("vault_did", help="DID of the vault being unlinked.")
    p_vault_unlink.add_argument("project_id", help="Project id unlinked at the vault.")
    p_vault_unlink.add_argument(
        "--reason", default=None, help="Optional reason recorded on the unlink event."
    )
    p_vault_unlink.add_argument(
        "--yaml", default=None,
        help="Path to your tn.yaml. Default: discover via the standard chain.",
    )
    p_vault_unlink.set_defaults(func=cmd_vault_unlink)

    # --- tn firehose (gated) -----------------------------------
    # Surface only when TN_FIREHOSE_ENABLED=1 at parser-construction
    # time. Same shape as the vault server's TN_DEV_AUTH_BYPASS gate:
    # absence at import/build time means the verb does not appear in
    # ``tn --help`` and dispatch raises the usual unknown-verb error.
    if _firehose_enabled():
        _register_firehose_subcommands(sub)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
