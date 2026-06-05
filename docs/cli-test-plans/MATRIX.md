# CLI parity + test matrix (single source of truth)

Axis legend (honest grading — what is *actually* tested, not "handler has a unit test"):
`✓` real round-trip tested · `⚠️` partial / coverage-only / fixture-fed · `✗` none ·
`🔌` built but not wired (not callable) · `▢` blocked (needs infra/feature first) · `—` N/A.

Axes: **SL orig** same-language originate · **SL recv** same-language receive (real produce→consume) ·
**XL orig** cross-language originate (this lang produces, other consumes) · **XL recv** cross-language receive ·
**Web recv** browser consumes a CLI-produced artifact · **Web tgt** browser produces → CLI consumes.

LOC = handler body (Py `cmd_*` / TS `*Cmd`).

| Verb | Py LOC | TS LOC | Exceptions | SL orig | SL recv | XL orig | XL recv | Web recv | Web tgt | Test cases (detailed) |
|---|---|---|---|---|---|---|---|---|---|---|
| init | 235 | 132 | TS +warmAttach | ⚠️ | — | ✓ | — | ✗ | ✗ | PASS: scaffold writes tn.yaml+keystore+identity; idempotent re-init no-op; row_hash byte-equal to other lang (`ceremony_init_parity`). FAIL: bad profile rejected; existing-ceremony not clobbered. |
| seal | 🔌36 | 45 | Py not wired; public-only | ⚠️ | — | ⚠️ | — | ✗ | ✗ | PASS: stdin JSON→envelope ndjson, 7 fields, row_hash+Ed25519 sig correct, byte-identical to other-lang seal of same input. FAIL: missing seed/event_type/etc→exit2; malformed JSON→exit2; blank line skipped. **[FIXED] TS seal/verify device_identity bug fixed; real seal→verify round-trip now tested.** |
| verify | 🔌46 | 96 | Py not wired; public-only | — | ✓ | — | ⚠️ | ✗ | ✗ | PASS: real `seal` output → ok:true; row_hash recomputes; sig verifies. FAIL: tampered field→ok:false; bad signature→ok:false; broken prev_hash chain→ok:false; encrypted-group payload rejected; malformed JSON→exit2. **[FIXED] real seal→verify chain tested (Py 8 / TS 8) + all FAIL cases.** |
| canonical | 🔌17 | 7 | Py not wired | ✓ | — | ⚠️ | — | — | — | PASS: JSON→canonical UTF-8 bytes; nested keys sorted; byte-identical Py↔TS for same input. FAIL: bad JSON→exit2; blank line skipped. |
| info | 🔌34 | 14 | Py not wired; `_sign` bug | ✓ | — | ✓ | — | ✗ | ✗ | PASS: appends one attested entry; `read` returns same event_type/level/fields. FAIL: missing --yaml/--event→exit2; bad `--field`→exit2. |
| read / secure_read | 45 | 32 | secure_read not in TS CLI | — | ✓ / ⚠️ | — | ✓ | ✗ | ✗ | PASS: emit N entries via real `info`→read back in order, fields match; secure_read ok for genuine. FAIL: tampered row_hash→secure_read raises; forged Ed25519 sig→raises; broken prev_hash→raises; --since filter; encrypted field unreadable w/o key. **[FIXED] forged-sig + chain-break tamper tests added (Py+TS), mutation-proven to bite the specific check; Py secure_read happy-path covered.** |
| watch | 49 | 93 | — | — | ✓ | — | ✓ | — | ✗ | PASS: `info`→`watch --once` streams the new entry decoded; rotation/truncation handled (`watch_interop` XL). FAIL: bad --since; corrupt line. |
| bundle | 26 | 131 | **TS seal-for-recipient STUB** | ⚠️ | — | ⚠️ | — | ✓ | — | PASS: produces .tnpkg kind=kit_bundle, toDid=recipient, group; **--seal-for-recipient actually seals (TS errors instead)**. FAIL: seal+placeholder DID→exit2. Web recv: browser opens the kit (e2e). |
| add_recipient | 68 | 109 (admin 14) | TS seal writes unsealed | ⚠️ | — | ⚠️ | — | ✓ | — | PASS: mint kit for group+recipient→kit_bundle; label→`did:key:zLabel-*` placeholder. FAIL: seal+label→exit2; **real DID +seal must seal (TS writes unsealed)**. Web recv: e2e Frank receives. |
| compile | 🔌39 | 37 | Py not wired; `--label` not persisted | ✓ | — | ⚠️ | — | ✗ | — | PASS: pack `.btn.mykit`→.tnpkg; manifest kind=kit_bundle, kits present, sig valid, absorbable. FAIL: missing keystore→exit2; **--label persisted (Py drops it)**. |
| group add | 31 | 118 | TS ensureGroup lacks fields param | ✓ | — | ✗ | — | — | — | PASS: new group lands in authoritative yaml+keystore, routable; --fields routed; cipher default=ceremony. FAIL: dup group; bad cipher. |
| rotate | 165 | 138 | — | ⚠️ | — | ⚠️ | — | ✗ | ✗ | PASS: rotate group→new epoch kit; post-rotation a revoked leaf cannot read, a current recipient can. FAIL: rotate unknown group; revoked-leaf reuse classified (equivocation). |
| absorb | 62 | 150 | — | — | ✓ | — | ✓ | — | ✗ | PASS: real kit (bundle/compile, other ceremony)→absorb installs `<group>.btn.mykit` ON DISK; accepted count; **recipient can then read publisher entries**; exit 0. FAIL: self-absorb→exit2 (unless --allow-self-absorb); garbage pkg→rejected; overwrite backs up prior. **[FIXED] real round-trip: install + read-back asserted (Py CLI test added). Unsealed kit decryptable by any recipient — binding needs sealing (TS gap).** |
| inbox accept | 166 | 268 | **synthetic only; bug** | — | ▢ | — | ✗ | — | ▢ | PASS(when buildable): real invite zip→installs `<group>.btn.mykit`, sha256 verified, `tn.enrolment.absorbed` recorded, recipient reads. FAIL: missing manifest→exit1; sha256 mismatch→exit1; garbage zip→exit1; missing yaml→exit1. **BLOCKER: no CLI invite-mint verb (only tn_proto_web mints). BUG: accept reads `kit.tnpkg`, server names it `<group>.btn.mykit`.** |
| inbox list-local | 20 | 113 | — | — | — | — | — | — | — | PASS: dir with `tn-invite-*.zip`→lists sorted asc; empty dir→"No ... found"; missing dir→empty, exit 0. FAIL: (none — never raises). |
| wallet sync | 73 | 587 | **both tests MOCK**; Py push deprecated | ⚠️ | ✗ | ✗ | ✗ | ✗ | ✗ | PASS: push body (AWK/BEK no-AAD frame)→pull/restore→**pushed bytes==restored bytes** (`plumb_awk_bek` MATCH bar); pull absorbs inbox snapshots; informed-equivocation surfaced. FAIL: wrong passphrase→BEK unwrap fail; If-Match conflict on concurrent push; tampered blob; not-linked→die. **Gap: needs live vault; only `plumb_awk_bek.mts` is real (not in suite).** |
| wallet restore | 72 | 32 | both MOCK; passphrase 0 cov | — | ✗ | — | ✗ | ⚠️ | ✗ | PASS: real pushed backup→restore into empty dir→keystore+yaml byte-match originals; restored ceremony reads its prior entries + signs new + read(verify=True). FAIL: wrong passphrase/mnemonic; missing project; tampered/partial blob. **Gap: needs live vault; passphrase path 0 coverage both langs.** |
| account connect | 74 | 64 | Py cmd 0 cov | — | ⚠️ | — | — | — | ✗ | PASS: mint code→connect→ok+account_id+project binding; `.tn/sync/state.json` account_bound:true; global identity stamped linked_account_id; exit 0. FAIL: expired/invalid/already-redeemed code; wrong DID sig; no --vault & no linked_vault. **Gap: TS real but skips w/o vault; Py mocked.** |
| wallet status | 45 | ✓(bin) | — | — | — | — | — | — | — | PASS: prints identity + link state + pending sync-queue (10 tests, real subprocess). FAIL: corrupt identity. |
| wallet link / unlink | 41/20 | 42/6 | parity | — | — | — | — | — | — | PASS: link writes ceremony.linked_vault+project; unlink clears (yaml-only). FAIL: link missing args. |
| wallet pull-prefs | 20 | 142 | TS `--help` crash; SDK getPrefs gap | — | ⚠️ | — | — | — | — | PASS: GET account/prefs→writes default_new_ceremony_mode+prefs_version to identity.json (needs vault). FAIL: no --vault & no cached→exit1. |
| wallet export-mnemonic | 25 | 144 | SDK mnemonic accessor gap | ✓ | — | — | — | — | — | PASS: --yes + stored phrase→prints banner, exit0. FAIL: no phrase→exit2; no --yes→withheld exit2; missing identity→exit1. |
| show env | 19 | 37 | — | ✓ | — | — | — | — | — | PASS: prints ceremony config snapshot. |
| show profiles | 64 | 119 | **TS catalog missing `stdout`** | ✓ | — | ✓ | — | — | — | PASS: prints 5-profile catalog matrix + blurbs (Py); JSON mode. FAIL: — . **Gap: TS catalog has 4 profiles, telemetry diverges → not byte-identical (`profile_chain_parity` XL).** |
| streams | 49 | 60 | — | ✓ | — | — | — | — | — | PASS: lists .tn ceremonies (human/json). FAIL: bad project dir. |
| validate | 186 | 72 | Py far more thorough | ✓ | — | — | — | — | — | PASS: validates .tn tree; Py checks deeper invariants. FAIL: malformed yaml/keystore. |
| firehose stats/list/get | 61 | 332 | both mock fetch; gated | — | ⚠️ | — | — | — | — | PASS: GET stats/incoming/snapshot with bearer→JSON (sort_keys) / bytes to --out; gating via TN_FIREHOSE_*. FAIL: non-200→die2; missing token→die1; missing URL→die1. |
| vault link / unlink | 🔌44 | 41 | Py not wired | ✓ | — | — | — | — | — | PASS: emits tn.vault.linked/unlinked attested event to admin log; receipt has event_id+row_hash. FAIL: unknown subcommand; missing positionals. |

## Cross-cutting blockers (gate the ✗/▢ cells)
1. **No CLI invite-mint verb** → `inbox accept` SL recv + Web tgt blocked until built (only `tn_proto_web/routes_invite.py` mints the `tn-invite-*.zip`).
2. **No live-vault test harness in CI** → `wallet sync`, `wallet restore`, `account connect`, `wallet pull-prefs` real round-trips need the dev vault (`TN_DEV_AUTH_BYPASS=1`, `/dev/login`, mint routes). `plumb_awk_bek.mts` is the working template; not in the suite.
3. **No signature-forgery / chain-break tamper test anywhere** → a regression skipping Ed25519/prev_hash verification passes green today (`verify`, `secure_read`).
4. **6 Python verbs not wired** (`seal verify canonical info compile vault`) → not callable as `tn <verb>`.

## Bugs — all FIXED 2026-06-05 (commits 98011b2, 0f8cb26, 6dca313, 7e8c64c)
- [FIXED] `inbox accept` read only `kit.tnpkg`; server names it `<group>.btn.mykit` → matches both now.
- [FIXED] `add_recipient --seal-for-recipient` on a real DID silently wrote an UNSEALED bundle → refuses consistently now (bundle already did). **Real TS sealing remains a GAP.**
- [FIXED] `compile --label` not persisted → now written into the signed manifest `state`.
- [FIXED] `cli_info` `_sign` type / field-hijack → `_sign=None` pinned.
- [FIXED] `wallet pull-prefs --help` crashed into a vault fetch → prints usage, clean exit.
- [FIXED · DISCOVERED] `tn-js seal`/`verify` were BROKEN at HEAD — the 0.4.3a1 `device_identity` naming flip missed `sealCmd`/`verifyCmd` (still passed `did`) → fixed; verify round-trip 8/8.
- [FIXED · DISCOVERED] `tn bundle` read `args.recipient_did` vs registered `recipient_identity` (AttributeError before minting) → fixed.

## New finding (protocol reality, not a bug)
- An unsealed `btn` kit_bundle is decryptable by ANY recipient (group read-key ships in clear; `recipient_identity` is attestation-only). Recipient *binding* requires `--seal-for-recipient`, which TS cannot do yet — so "wrong recipient can't decrypt" is NOT assertable for unsealed kits.

## Still open
- No CLI **invite-mint verb** → `inbox accept` full round-trip blocked.
- No **live-vault CI harness** → `wallet sync`/`restore`/`account connect`/`pull-prefs` real round-trips.
- 6 Python verbs **not wired** (`seal verify canonical info compile vault`) — still 🔌.
- Real **seal-for-recipient** not implemented in TS (verbs refuse it safely).
