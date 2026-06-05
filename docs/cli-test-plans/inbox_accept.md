# Test plan: `inbox accept` — same-language round-trip

Status: **plan / audit only**. No new tests written or run by this document.
Existing tests were run once for the audit (results below).

Scope: the `inbox accept` verb (Python `python/tn/inbox.py::accept`; TypeScript
`ts-sdk/src/cli/inbox_accept.ts`) and the question of whether a *real*
`tn-invite-*.zip` can be produced same-language (CLI-side) so the round-trip
exercises a genuinely-minted invitation rather than a hand-built fixture.

---

## 0. Headline finding (read this first)

**There is no CLI/SDK verb in `tn_proto` that mints a `tn-invite-*.zip`.**

The outer invitation wrapper (`manifest.json` + the inner kit entry) is produced
**only** server-side, by the web vault:

- `tn_proto_web/src/routes_invite.py::_make_invitation_zip` (lines 174-194) is
  the sole function in the entire tree that writes a zip containing
  `manifest.json` alongside a kit entry. It is called from the two FastAPI
  endpoints `invite_reader` (`POST /projects/{id}/invite`, line 369) and
  `upload_invitation` (`POST /projects/{id}/upload-invitation`, line 504).

The `tn_proto` CLI/SDK only mints the **inner kit**, never the wrapper:

- `tn add_recipient` → `python/tn/cli.py::cmd_add_recipient` (line 1413) →
  `pkg.bundle_for_recipient(...)` writes a bare `<label>.tnpkg` kit bundle.
- `tn bundle`, and `tn admin add-recipient --out <kit-path>` (TS:
  `ts-sdk/bin/tn-js.mjs` line 619) likewise emit a bare `.mykit`/`.tnpkg`.
- `allocate_worker.py` (the server's subprocess) calls
  `tn.admin.add_recipient(group, recipient_did=..., out_path=..., raw=True)`
  (line 63) — again, a **bare kit file**. The wrapper is added *afterward* by
  `_make_invitation_zip`, which lives in `tn_proto_web`, not `tn_proto`.

**Consequence:** a faithful same-language CLI round-trip
(`mint invite zip → inbox accept`) is **not possible today using only
`tn_proto`**. The invite-mint half of the round-trip lives in a different repo
(`tn_proto_web`) and is gated on Mongo + FastAPI + vault auth + a provisioned
publisher keystore. To get a real round-trip inside `tn_proto`, an
**invite-mint verb must be built first** (see §7).

---

## 1. Flow — what really mints a `tn-invite` zip

### Real production path (server-side, `tn_proto_web`)

```
Alice clicks "Invite" in the dashboard
  → POST /api/v1/projects/{id}/invite            routes_invite.py::invite_reader
      → _allocate_in_subprocess(...)             runs allocate_worker.py in a subprocess
          → tn.admin.add_recipient(group, recipient_did, out_path, raw=True)
            writes a bare  <out>.btn.mykit  (the inner kit)
          → returns (kit_bytes, leaf_index, kit_sha256, event_id)
      → manifest = { invitation_id, from_account_did, from_email, project_id,
                     project_name, group_name, leaf_index, kit_sha256,
                     event_id, created_at, note }
      → zip_bytes = _make_invitation_zip(kit_bytes, manifest)
            zip entries:
              "<group>.btn.mykit"  (kit bytes; native keystore filename)
              "manifest.json"      (json.dumps(manifest, indent=2))
      → invitations().insert_one({... "body": Binary(zip_bytes) ...})   (Mongo)

Frank downloads:
  → GET /api/v1/inbox/{id}/download              routes_invite.py::download_invitation
      → Response(body, media_type="application/zip",
                 Content-Disposition filename="tn-invite-{id}.tnpkg")
```

Note an inner-name nuance: the **server** names the inner kit entry
`<group>.btn.mykit` (`_kit_entry_name`, line 162), but the **accept** verb on
both languages reads the inner entry by the name `kit.tnpkg`
(`inbox.py` line 110; `inbox_accept.ts` line 154). The Python module docstring
and the `_kit_entry_name` docstring both note `kit.tnpkg` is the legacy
wrapper-internal name accepted as a fallback — but the current `accept`
implementations only look up `kit.tnpkg`, **not** `<group>.btn.mykit`. This is a
latent real-vs-fixture mismatch (see §7).

There is no per-language divergence in *who mints the zip*: both the Python and
TS `accept` verbs consume a wrapper that only `tn_proto_web` (Python/FastAPI)
produces. The TS SDK has no invite-mint path at all.

### Accept path (consumes the zip — `tn_proto`, both languages)

- Python: `python/tn/inbox.py::accept` (line 61) / `_cmd_accept` (line 187) /
  `main()` accept branch (line 242).
- TS: `ts-sdk/src/cli/inbox_accept.ts::accept` (line 109) / `inboxAcceptCmd`
  (line 225); dispatched from `ts-sdk/bin/tn-js.mjs::inboxCmd` (line 1552,
  `tn-js inbox accept <zip> [--yaml]`).

Both: unzip → read `manifest.json` → read `kit.tnpkg` → verify `kit_sha256` →
install as `<group_name>.btn.mykit` under the ceremony keystore dir (backing up
any prior kit to `.previous.<UTC_TS>`) → record `tn.enrolment.absorbed` to the
local log (non-fatal on failure) → exit 0.

---

## 2. What it would take to actually work

**Plainly: the same-language CLI round-trip cannot be built today without a new
invite-mint verb.** The invite-production half is browser/vault-only.

Two ways to close the gap:

1. **Build a CLI invite-mint verb in `tn_proto`** (preferred for a self-contained
   round-trip). Conceptually: `tn invite <group> <recipient-did> [--out tn-invite-X.zip]`
   that (a) calls the existing `admin.add_recipient(..., out_path=..., raw=True)`
   to mint the bare kit + read `leaf_index`/`kit_sha256`, then (b) wraps it with
   a `manifest.json` exactly as `_make_invitation_zip` does. This is a thin shim
   over code that already exists — the kit mint is `add_recipient`; the wrapper
   is ~15 lines (the `zipfile.writestr` of `manifest.json` + the kit). It would
   let mint and accept be exercised in one process, same language.

2. **Drive the real server path** (`tn_proto_web`) — stand up Mongo + FastAPI +
   a provisioned publisher keystore, `POST /invite`, `GET /download`, feed the
   downloaded bytes to `inbox accept`. This is a cross-repo integration test, not
   a `tn_proto` same-language CLI test, and is heavyweight (Mongo, auth, vault
   state). It also lives in the wrong repo for a `tn_proto` test suite.

Until one of these exists, every `inbox accept` test in `tn_proto` is forced to
**hand-build** the wrapper (which is exactly what the current tests do).

---

## 3. Setup / preconditions

For a real round-trip (assuming the §7 invite-mint verb is built):

1. **Ceremony**: a fresh btn ceremony with `tn_core` (Rust) active —
   `add_recipient` requires the Rust runtime (`allocate_worker.py` line 50
   guards `tn.using_rust()`). Python: `tn.init(yaml)`; TS: `await Tn.init(yaml)`.
2. **Recipient identity**: a real recipient device DID (`did:key:z...`). For btn
   sealing a *real* key-DID is required; synthesized `did:key:zLabel-*`
   placeholders have no embedded public key (cli.py line 1450 rejects
   `--seal-for-recipient` for them).
3. **Produce a REAL invite zip**: call the new `tn invite ...` verb (or the
   server `POST /invite`). Today, **with `tn_proto` alone, no real invite zip can
   be produced CLI-side** — this is the documented blocker. The bare kit *can* be
   produced (`add_recipient`), but the `manifest.json` wrapper cannot.
4. **Accept**: run `inbox accept <zip> --yaml <ceremony.yaml>` from the
   recipient's ceremony.

For the *fixture* tests that exist today, the only precondition is a fresh
ceremony + a hand-assembled wrapper zip (no recipient allocation, no real kit
binding).

---

## 4. PASS conditions

A correct accept of a genuine invitation must:

1. Exit **0**.
2. Install the kit as `<group_name>.btn.mykit` under the ceremony keystore dir
   (Python: `keystore.path` resolved via the yaml, default `./.tn/keys`;
   TS: `tn.config().keystorePath`).
3. The installed kit bytes equal the kit bytes the inviter minted.
4. `kit_sha256` in the manifest **verifies** against the kit bytes
   (`_verify_kit_hash` / `verifyKitHash`).
5. Record a `tn.enrolment.absorbed` event to the recipient's local log
   (`group`, `from_did`, `package_sha256`, `absorbed_at`).
6. Print `Installed kit for group '<g>' (leaf <n>) from <email>.`, the kit path,
   and an `Absorbed at: <iso8601>` line.
7. **Recipient can subsequently read** the inviter's data with the installed
   kit (the end-to-end proof a fixture cannot give).

Real-round-trip strengthening (vs the fixtures): PASS #3, #4, #7 only mean
something when the kit was minted by a real `add_recipient` against a real
ceremony and bound to the recipient's real DID. The current fixtures satisfy
#1, #2, #6 and a *self-referential* #4 (manifest hash computed over fixture
bytes), but #3/#7 are vacuous for arbitrary kit bytes.

---

## 5. FAIL conditions (each MUST be caught → exit 1)

1. **Missing zip** → `Error: Zip not found: <path>` (inbox.py line 77;
   inbox_accept.ts line 115).
2. **Missing `tn.yaml`** → `Error: tn.yaml not found at <path>. ... pass --yaml`
   (line 83 / 120).
3. **Garbage / non-zip bytes** → `Error: Invalid zip file: <...>`
   (`BadZipFile` line 94 / `parseTnpkg` throw line 133).
4. **Missing `manifest.json`** → `Error: Invalid invitation zip: missing
   manifest.json` (line 100 / 140).
5. **Missing kit entry** → `Error: Invalid invitation zip: missing kit.tnpkg`
   (line 112 / 156).
6. **`kit_sha256` mismatch** → `Error: Kit hash mismatch. Expected/Got ...
   Re-download from the vault.` (line 52 / 86). Both `sha256:`-prefixed and
   bare-hex expectations are handled.
7. **Unloadable `tn.yaml`** (exists but not a valid ceremony) →
   `Error: Could not read tn.yaml: <...>` (line 125 / 168).
8. **Corrupt manifest JSON** → not an `InboxError`; the underlying JSON error
   propagates (not swallowed to exit 1). TS asserts a `SyntaxError` re-throw
   (test line 375); Python would raise `json.JSONDecodeError` out of `accept`.

A real-round-trip suite should additionally cover: a kit bound to the **wrong
recipient DID** (accept installs it, but step #7 read fails — the meaningful
negative a fixture cannot produce), and a manifest whose inner kit entry is named
`<group>.btn.mykit` rather than `kit.tnpkg` (the real server name — see §1 / §7).

---

## 6. Current test audit

### TypeScript — `ts-sdk/test/cli_inbox_accept.test.ts`

**Run once (this audit): 14/14 pass** (`node --import tsx --import
./test/_setup_wasm.mjs --test test/cli_inbox_accept.test.ts`, after
`npm run build`).

**Input is hand-built.** The helper `buildInviteZip(...)` (lines 72-104)
synthesizes the manifest *in-test* and packs it with `packTnpkg`:

- line 84: kit defaults to literal `"fake-kit-bytes-for-test"`;
- lines 86-92: `manifest` object assembled in JS, `kit_sha256` computed in-test
  (or overridden to force a mismatch);
- lines 94-103: pushes `{name:"manifest.json"}` and `{name:"kit.tnpkg"}` and
  returns `packTnpkg(entries)`.

It is called at lines 112, 154, 160, 184, 204, 225, 261, 300, 319, 338, 359,
405. The happy-path test (line 106) is the only one that uses *genuine* kit
bytes — but those are the **ceremony's own `default.btn.mykit`** read back off
disk (`realKit`, line 65), not a kit minted *for a recipient* by
`add_recipient`. So even the happy path does not exercise a real
inviter→recipient allocation; it re-installs the ceremony's self-kit.

Coverage vs §4/§5:

| Condition | Covered | Test |
|---|---|---|
| PASS exit 0 + install + stdout | yes | "happy accept ..." (106) |
| PASS installed bytes == kit bytes | yes (self-kit) | line 130 |
| PASS `tn.enrolment.absorbed` recorded | **no** — hits the non-fatal warn branch (test asserts the Warning, line 137) | "happy accept ..." |
| PASS recipient can subsequently read | **no** | — |
| PASS backup of prior kit | yes | "accepting over an existing kit" (144) |
| PASS no-hash skip | yes | line 181 |
| FAIL missing zip | yes | line 241 |
| FAIL missing yaml | yes | line 258 |
| FAIL garbage zip | yes | line 278 |
| FAIL missing manifest | yes | line 297 |
| FAIL missing kit | yes | line 316 |
| FAIL hash mismatch (prefixed + bare) | yes | lines 200, 222 |
| FAIL unloadable yaml | yes | line 352 |
| FAIL corrupt manifest re-throw | yes | line 375 |
| default-yaml-in-cwd | yes | line 335 |
| lower `accept()` result shape | yes | line 400 |

### Python — `python/tests/test_inbox_accept.py`

Same shape, also hand-built. `_make_zip(...)` (lines 41-47) writes
`zf.writestr("kit.tnpkg", kit_bytes)` + `zf.writestr("manifest.json", ...)` with
a manifest dict assembled in-test. Happy path (line 119) mocks `tn.init`,
`tn.info`, `tn.flush_and_close` so the **attestation is faked, not really
recorded** (captured into a list, line 143). Covers: missing zip (77), missing
manifest (86), hash mismatch (101), happy install + mocked attestation (119),
backup of existing kit (172), `list_local` (211, 224). Does **not** cover:
garbage/non-zip, unloadable yaml, corrupt-manifest propagation, no-hash skip, or
any real read-back.

### Verdict

**Confirmed synthetic fixture on both languages.** The manifest is synthesized
in-test (`buildInviteZip` in TS; `_make_zip`/inline dict in Python); kit bytes
are arbitrary literals (or, on the TS happy path, the ceremony's own self-kit) —
**never a kit minted for a recipient by `add_recipient`, and never a wrapper
produced by `_make_invitation_zip`.** The tests faithfully cover the accept
verb's parsing/validation/stdout/exit-code contract, but **none exercises a real
produced invitation**, and neither verifies the two properties that only a real
round-trip can prove: a recipient-bound kit and a successful subsequent read.

---

## 7. Gap to a real round-trip test

**Yes — an invite-mint verb must be BUILT first** for a same-language CLI
round-trip inside `tn_proto`. Concretely:

1. **Add `tn invite <group> <recipient-did> [--out tn-invite-<id>.zip]`** (and
   the TS `tn-js invite` peer). It would:
   - call `admin.add_recipient(group, recipient_did=..., out_path=<tmp kit>,
     raw=True)` to mint the bare kit and read `leaf_index` + compute
     `kit_sha256` (the exact logic already in `allocate_worker.py` lines 63-72);
   - assemble a `manifest.json` (group_name, leaf_index, from_email,
     from_account_did, kit_sha256, ...) and zip it next to the kit — the exact
     logic already in `routes_invite.py::_make_invitation_zip`.
   This is a shim over existing primitives; the only genuinely new code is the
   ~15-line wrapper, which could be **factored into a shared `tn_proto` helper**
   that both the new CLI verb and `tn_proto_web` import (removing the current
   duplication where `_make_invitation_zip` reimplements wrapping in the web
   repo).

2. **Reconcile the inner-entry name.** The server writes the inner kit as
   `<group>.btn.mykit`; `accept` reads `kit.tnpkg`. A real round-trip must pick
   one and the other side must accept it. Either teach `accept` to fall back to
   `<group>.btn.mykit` (as its own docstring claims it already does, but the code
   does not), or have the new mint verb write `kit.tnpkg`. **This mismatch is
   itself a real-vs-fixture bug the current synthetic tests mask** — the fixtures
   always name the inner entry `kit.tnpkg`, so they never hit the server's actual
   naming.

3. **Then write the round-trip test**: fresh ceremony → `tn invite` produces a
   real `tn-invite-*.zip` bound to a second ceremony's DID → `inbox accept`
   installs it → assert the §4 PASS set **including #7 (recipient reads the
   inviter's data with the installed kit)** and the §5 wrong-recipient negative.

Absent (1)+(2), the suite is stuck at fixture parity: a correct, well-covered
test of the *accept* verb's input handling, but not a proof that a genuinely
minted invitation round-trips.
