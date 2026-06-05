# `read` / `secure_read` / `watch` — SAME-LANGUAGE round-trip test contract

Scope: the read-side verbs decoding a genuine attested entry produced by the
**same** language runtime's originate verb (`info` / `tn.info` / any emit). This
is the true round-trip: an emit verb appends an attested, encrypted, signed,
chained ndjson entry; `read` / `secure_read` / `watch` open the same ceremony
and decode it back into a typed `Entry`. No hand-written log files, no
fixtures — the bytes on disk are the bytes the emit verb wrote.

Three read surfaces, layered:

- **`read`** — decrypt + decode every row to a typed `Entry`. Integrity checks
  are OFF by default (a tampered row still comes through).
- **`secure_read`** — `read` with fail-closed verification. Each row's
  `row_hash` is recomputed, the Ed25519 `signature` is checked against the
  signer's key, and the `prev_hash` chain is walked. In the current code this
  is `read(verify=…)` / `read({verify})`: `verify="skip"` drops invalid rows
  (and emits `tn.read.tampered_row_skipped`), `verify="raise"` / `verify=true`
  throws on the first invalid row.
- **`watch`** — `read` that tails live: it follows the log file (poll +
  rotation/truncation aware) and yields each new `Entry` as it lands.

---

## 1. Flow

### Python

```
emit verb                         on-disk ndjson                read-side verb
tn.info(event, **fields)   -->    { device_identity, seq,  -->  tn.read()            -> Entry(event_type, level, fields, …)
  (or cli_info.cmd_info,          prev_hash, row_hash,           tn read (cmd_read)   -> one line per Entry
   or tn.log(..., level=))        signature, <group blocks>      python -m tn         -> Entry.model_dump_json / row
                                  + equality-index tokens)       tn.read(verify=…)    -> secure_read: sig+chain checked
                                                                 python -m tn.watch   -> JSONL tail of new Entry rows
```

- **emit**: `cli_info.cmd_info` (`python/tn/cli_info.py:57`) binds the ceremony
  with `tn.init(args.yaml)` then routes to `tn.info` for the four standard
  levels or `tn.log(..., level=…)` for any other level string. `tn.info` /
  `tn.log` is the only thing that does the encrypt / chain / sign work; the verb
  itself is a thin parse-and-dispatch shim.
- **`read`**: `cli.py:cmd_read` (`cli.py:1747`) re-binds, resolves a stream name
  or literal log path, iterates `tn.read(...)`, prints `ts level event_type
  k=v…` per `Entry` (`cli.py:1778-1788`). `python -m tn`
  (`python/tn/__main__.py`) auto-discovers the ceremony and emits
  `Entry.model_dump_json` (or `--raw` envelope dicts) per row, with optional
  `--verify skip|raise`.
- **`secure_read`**: `_read_impl._secure_read_impl`
  (`python/tn/_read_impl.py:43`) is the fail-closed read; surfaced via
  `tn.read(verify=…)` and `python -m tn --verify`. `VerifyError` carries the
  failing envelope + `invalid_reasons` (`_read_impl.py:17-29`).
- **`watch`**: `python -m tn.watch` (`python/tn/watch.py`) binds, coerces
  `--since` (`start` / `now` / seq int / ISO ts), and either drains once
  (`--once`, via `tn.read(verify=True, all_runs=True)`) or tails forever via the
  async `tn.watch(since=…, verify=True, …)`, writing `entry.model_dump_json()`
  per line.

### TypeScript

```
emit verb                         on-disk ndjson                read-side verb
tn-js info --event … --field …  -> { device_identity, seq, -->  tn-js read --yaml …  -> JSON {event_type, plaintext, valid…}
  (NodeRuntime.init + rt.emit)     prev_hash, row_hash,          client.read()         -> Entry
                                   signature, <group blocks>)    client.read({verify}) -> secureRead: sig+chain checked
                                                                 tn-js watch --yaml …  -> JSONL tail
```

- **emit**: `infoCmd` (`ts-sdk/bin/tn-js.mjs:273`) → `NodeRuntime.init(yaml)` +
  `rt.emit(level, event, fields)`; prints `{event_id, row_hash, sequence}`.
  `parseFieldArgs` (`tn-js.mjs:249`) builds the fields dict (`--field k=v`,
  `--int`, `--bool`).
- **`read`**: `readCmd` (`tn-js.mjs:288`) → `NodeRuntime.init` + `rt.read(log)`,
  printing `{event_type, sequence, timestamp, device_identity, row_hash,
  plaintext, valid}` per entry (`--compact` for one-line JSONL). Library:
  `Tn.read()` → `Entry` (`ts-sdk/src/tn.js`, shape in
  `ts-sdk/src/core/read_shape.ts`).
- **`secure_read`**: `Tn.read({verify})` (the `secureRead` successor — see the
  migration note atop `ts-sdk/test/secure_read.test.ts`). `verify:"skip"` drops
  invalid rows, `verify:"raise"` / `verify:true` throws `VerifyError`
  (`ts-sdk/src/Entry.js`). **There is no `secure_read` / `--verify` flag wired
  into `readCmd` in `bin/tn-js.mjs`** — secure_read is a library-only surface on
  the TS CLI today. `watch --verify` is the only CLI path that runs
  verification.
- **`watch`**: `watchCmd` (`tn-js.mjs:321`) parses `--yaml`, `--since`,
  `--verify`, `--poll`, `--once`, then drives `Tn.watch` (live) or `tn.read`
  (`--once` snapshot), writing one JSON object per line.

---

## 2. What it would take to actually work

A real round-trip — not a fixture, not a hand-edited ndjson file:

1. **Real ceremony.** `tn.init(<yaml>)` (Python) / `NodeRuntime.init(<yaml>)`
   (TS) mints a real device identity + group keys at a fresh, isolated path.
2. **Real emitted entry.** Append N entries through the **real emit verb**
   (`cmd_info` / `tn.info` / `tn.log` in Python; `infoCmd` / `rt.emit` in TS)
   with known `event_type`, `level`, and `fields`. The encrypt / chain / sign
   machinery runs for real.
3. **Read it back.** Re-bind the same ceremony and run `read` / `secure_read` /
   `watch` against the on-disk log the emit verb wrote.
4. **Assert the decoded `Entry` matches what was emitted** — same
   `event_type`, `level`, decrypted `fields`, in `sequence` order; and for
   `secure_read`, that the signature + `row_hash` + chain verify clean.

The load-bearing property is that step 2 writes the bytes step 3 reads. A test
that hand-authors an ndjson line and reads it back proves the parser, not the
protocol round-trip.

---

## 3. Setup / preconditions

- Isolated `TN_HOME` / identity dir + working dir per test (no singleton bleed,
  no real vault contact: `TN_NO_LINK=1`, `TN_NO_STDOUT=1`).
- Init a ceremony at an explicit yaml path; pin the cipher (`cipher="btn"`) so
  the fields actually go through group encryption.
- Emit N entries with **known** `event_type` / `level` / `fields`, e.g.
  `order.created {amount:100, order_id:"A100"}` at `info`, plus one at a
  non-standard level (`trace`) to cover the `tn.log` branch.
- For `watch`: disable session-start log rotation (`rotate_on_init: false`) so
  the read-side `init()` does not roll the just-written rows into `<log>.1`
  (the pattern `cli_watch.test.ts` already uses), then either start the tail
  before appending (live `since="now"`) or drain with `--once --since start`.
- Flush + close the writer before the reader re-binds (one `tn` flow per
  process), or read from a separate process/handle.

---

## 4. PASS conditions

- **`read`**: returns the same entries that were emitted — matching
  `event_type`, `level`, and decrypted `fields` — in `sequence` order. Exit 0.
  `--raw` returns the on-disk envelope dict (group `ciphertext` block present);
  default returns typed `Entry` with crypto plumbing on typed attributes
  (`row_hash` / `prev_hash` / `signature`), NOT in `fields`.
- **`secure_read`**: all of the above, AND every returned row verifies clean —
  recomputed `row_hash` matches, Ed25519 `signature` verifies against the
  signer key, `prev_hash` chain is contiguous. `verify="raise"` does not throw;
  `verify="skip"` returns the full set with no drops.
- **`watch`**: a row appended after the tail starts (`since="now"`) is streamed
  as a decoded `Entry`; `since="start"` replays pre-existing rows then streams
  new ones; `since=<seq>` / `since=<ISO>` resume from the right point. `--once`
  drains the current log and exits 0. JSONL shape carries `event_type`, `level`,
  `fields`, `did`, `row_hash` (starts `sha256:`), `prev_hash`, `signature`;
  the `ciphertext` block stays out of the dump.

---

## 5. FAIL conditions (MUST catch)

1. **Tampered row fails `secure_read`.** Flip a byte in a row's `row_hash` (or
   `ciphertext`) on disk after emit. `verify="raise"` / `verify=true` MUST throw
   `VerifyError` (Python) / `VerifyError` (TS); `verify="skip"` MUST drop that
   row and emit `tn.read.tampered_row_skipped`. Plain `read` (no verify) MUST
   still surface it (proves the check is what catches it, not the parser).
2. **Forged / missing signature.** Replace `signature` with a valid-length but
   wrong Ed25519 signature, or strip it. `secure_read` MUST reject the row
   (`invalid_reasons` includes the signature failure). **Gap: no current test
   forges/strips the signature specifically — every tamper test mutates
   `row_hash` only (see §6).**
3. **Broken chain.** Mutate one row's `prev_hash` so the chain is
   non-contiguous. `secure_read` MUST flag it.
4. **Wrong `--since` filter.** `watch --since now` MUST NOT replay pre-existing
   rows; `--since <future-seq>` / `<future-ts>` MUST skip everything already
   present; `--once --since now` MUST be a no-op (exit 0, no output).
5. **Encrypted fields not readable without the key.** A reader bound to a
   ceremony lacking the group key MUST NOT surface the plaintext `fields` (the
   `ciphertext` block stays opaque); decode degrades, it does not leak.

---

## 6. Current test audit

Verdict legend: **REAL** = entry emitted by the real emit verb then read back
(true round-trip). **PARTIAL** = real emit + read but a sub-property (e.g. sig
forgery, CLI verb itself) untested. **FIXTURE/NONE** = hand-written or absent.

### TypeScript

| Verb | Test | Round-trip? | Verdict |
|---|---|---|---|
| `read` (lib) | `ts-sdk/test/read_shape.test.ts:25-104` | `client.info("order.created", {...})` emit → `client.read()` decode; asserts `event_type`/`level`/`fields`/typed crypto attrs (`:33-49`); `raw:true` path (`:55-73`) | **REAL** |
| `read` (CLI) | `regression/crawl/c6_cli_verbs/ts_read_cross_cli.test.ts:39-139` | Python `tn.info` writes (`:84-100`), `tn-js read --compact` reads (`:111-136`). True round-trip but **cross-language** (Python→TS), not same-language `infoCmd`→`readCmd`. No same-language `infoCmd`→`readCmd` test found. | **PARTIAL** |
| `secure_read` (lib) | `ts-sdk/test/secure_read.test.ts:21-112` | `client.info("evt.good",…)` emit → tamper `row_hash` on disk → `read({verify:"skip"\|"raise"\|true})` drops/throws (`:34-87`); default `read` still surfaces (`:89-112`) | **REAL** (but `row_hash` only — see gaps) |
| `secure_read` (interop/bytes) | `ts-sdk/test/secure_read_interop.test.ts` | Byte-compares committed canonical fixtures across Py/Rust/TS. **Fixture-based**, not a live emit→secure_read round-trip; pins wire encoding, not the verify path. | **FIXTURE** (complements, not a substitute) |
| `watch` (lib) | `ts-sdk/test/watch.test.ts:17-197` | `tn.info(...)` emit → `tn.watch()` tail; covers `since=now`/`start`/`<seq>`/`<ISO>`, rotation, truncation | **REAL** |
| `watch` (CLI) | `ts-sdk/test/cli_watch.test.ts:9-45` | `Tn.init` + `tn.info` emit (`:14-15`) → spawn `tn-js watch --once --since start` → assert `event_type`s in stdout (`:39-41`), exit 0 | **REAL** |

### Python

| Verb | Test | Round-trip? | Verdict |
|---|---|---|---|
| emit (`cmd_info`) → `tn.read` (lib) | `python/tests/test_cli_info.py:130-183` | `cmd_info(...)` real emit → `_read_events` = `tn.read()` decode; asserts `event_type`/`level`/`fields` for info/warning/blank/trace branches (`:143-182`) | **REAL** |
| `read` CLI (`cmd_read`) | — | No test drives `cli.py:cmd_read` or `python -m tn` as a round-trip. `cmd_read` is referenced only by unrelated suites (`test_cli_show_env.py`, `test_cli_sync_pull.py`, `test_wallet_status.py`) for argparse plumbing, not an emit→`tn read`→assert flow. | **NONE** |
| `secure_read` | — | No dedicated `secure_read` / `tn.read(verify=…)` unit test. `secure_read` appears only incidentally in `test_admin_add_agent_runtime.py`, `test_init_autoabsorb.py`, `test_tnpkg_interop.py`, `integration/test_vault_push_pull_e2e.py` — none is a tamper / sig-forgery / chain-break assertion on the verify path. **No Python equivalent of `ts-sdk/test/secure_read.test.ts`.** | **NONE** |
| `watch` (lib) | `python/tests/test_watch.py:39-163` | `tn.info(...)` emit → `tn.watch()` tail; covers new appends, `since="start"` replay, main-vs-admin log split | **REAL** |
| `watch` CLI (`python -m tn.watch`) | `python/tests/test_watch.py:171-213` | `tn.init` + `tn.info("order.created",…)` real emit → subprocess `python -m tn.watch --once --since start` → asserts decoded `event_type`/`fields`/crypto-plumbing JSONL shape (`:192-212`) | **REAL** |

---

## 7. Gap to a real round-trip test

The emit→read round-trip is genuinely covered for the **library** `read` and
`watch` in both languages, the **`watch` CLI** in both languages, and the TS
**`secure_read` library** verb. The concrete gaps:

1. **Python `secure_read` has zero direct coverage.** No test emits a real
   entry then runs `tn.read(verify="raise"/"skip")` and asserts clean-verify on
   a good row + rejection on a tampered one. This is the single biggest hole —
   TS has `secure_read.test.ts`, Python has no equivalent. Mirror that suite:
   `tn.info` → tamper `row_hash` on disk → assert `VerifyError` (raise) / drop +
   `tn.read.tampered_row_skipped` (skip) / pass-through (default).

2. **No signature-forgery / missing-signature test in any language.** Every
   tamper test mutates `row_hash` only (`secure_read.test.ts:30,55,76,97`).
   §5.2 (forge / strip the Ed25519 `signature`) and §5.3 (break `prev_hash`
   chain) are unverified — a regression that skipped signature or chain
   verification while still checking `row_hash` would pass today. Add a row
   whose `signature` is replaced with a valid-length wrong value and assert
   rejection; add a `prev_hash`-mutation case.

3. **Python `tn read` CLI verb (`cmd_read`) and `python -m tn` are untested
   round-trips.** Coverage stops at the `tn.read` library call. A
   same-language `cmd_info`→`cmd_read` (or `python -m tn`) test — emit, then
   invoke the CLI verb, parse stdout, assert the entries — would close the CLI
   gap that `cli_watch.test.ts` already closes for `watch`.

4. **No same-language TS `infoCmd`→`readCmd` CLI round-trip.** The only `read`
   CLI round-trip is the cross-language `ts_read_cross_cli.test.ts`
   (Python writes, `tn-js read` reads). A same-language spawn of
   `tn-js info … && tn-js read …` is missing.

5. **`secure_read` is not exposed on the TS CLI at all.** `readCmd` has no
   `--verify` flag; only `watchCmd` runs verification. Either wire `--verify`
   into `readCmd` (then add the CLI round-trip), or document that CLI
   secure-read is `watch --verify` / library-only.

6. **§5.5 (encrypted fields unreadable without the key)** is asserted by the
   cross-publisher / `read_as_recipient` suites, not by the core read/secure_read
   suites here — worth an explicit negative assertion in this contract's scope
   (reader without the group key gets no plaintext `fields`).
