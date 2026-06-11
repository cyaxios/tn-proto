# `verify` — SAME-LANGUAGE round-trip test contract

Scope: the `verify` verb consuming a genuine `seal` envelope produced by the
**same** language runtime. Python: `tn.cli_seal.cmd_seal` → ndjson →
`tn.cli_verify.cmd_verify`. TypeScript: `bin/tn-js.mjs` `sealCmd` → ndjson →
`verifyCmd`.

This is the public-only path: no btn/JWE group encryption, `groups={}`, so the
envelope is a plain signed ndjson record (the 9 mandatory scalars +
public fields). A real attested log entry written by `info`/`tn.info` has the
same wire shape, so `verify` is also the validator behind the read path.

---

## 1. Flow

### Python

```
stdin JSON line                      stdin envelope ndjson line
{ seed_b64, event_type, level,       { device_identity, timestamp, event_id,
  sequence, prev_hash, timestamp, --> event_type, level, sequence, prev_hash, --> { "ok": true, "did", "event_type",
  event_id, public_fields }   seal     row_hash, signature, <public_fields> } verify   "event_id", "row_hash", "sequence" }
```

- `cmd_seal` (`python/tn/cli_seal.py`): derives `DeviceKey.from_private_bytes(seed)`,
  computes `row_hash` via `tn.chain._compute_row_hash(..., groups={})`, signs the
  `row_hash` bytes with Ed25519, renders a compact-ndjson envelope
  (`cli_seal.py:82-112`).
- `cmd_verify` (`python/tn/cli_verify.py`): requires the 9 scalars, rejects any
  leftover key whose value is a dict carrying `ciphertext` (group payload),
  recomputes `row_hash` over the remaining public fields, compares, then verifies
  the signature (`cli_verify.py:63-128`).

### TypeScript

Same contract, same field names. `sealCmd` (`tn-js.mjs:97-141`) uses
`DeviceKey.fromSeed` + `rowHash(...)` + `buildEnvelopeLine(...)`; `verifyCmd`
(`tn-js.mjs:143-238`) destructures the 9 scalars, splits `...rest` into public
fields vs `ciphertext`-bearing group payloads, recomputes `rowHash`, compares,
then `verify(did, rowHashBytes, sig)`.

The Python and TS envelopes are byte-identical for identical input (same
canonicalisation, same key order, same Ed25519 over the `row_hash` UTF-8 bytes) —
this is what `test/interop_driver.mjs` exists to prove.

### Stronger round-trip: `info` → read-raw → verify

A genuine log entry minted by `tn.info` (Python) / `tn.info` (TS) is itself a
verifiable envelope: same `row_hash` preimage, same signature over `row_hash`.
A higher-rigor round-trip is therefore **emit a real entry, read it back raw
(the dict envelope, `raw=True`), and feed that envelope to `verify`** — this
exercises the real writer's chain/sign code rather than a `seal`-only harness.
A real **ceremony** log line (the `tn init` ceremony genesis entries) read back
and verified is the strongest cross-source check, because the producer is the
ceremony writer, not the test's own seal call.

---

## 2. What it would take to actually work (a real round-trip)

1. **A real signing identity** — a 32-byte Ed25519 seed (Python
   `DeviceKey.from_private_bytes`, TS `DeviceKey.fromSeed`) so the `did`
   (`device_identity`) the signature is checked against is the one that signed.
2. **Seal output piped into verify** — run `seal` on a batch of inputs, take its
   stdout ndjson **unmodified**, and pipe it to `verify`. The chain is only real
   if `verify`'s input is `seal`'s actual output, not a re-derived fixture.
3. **For cross-source rigor** — instead of `seal`, produce the envelope from a
   real `tn.info` write (read-raw), and ideally verify a real **ceremony** log
   line, so the producer is independent of the verify test.

---

## 3. Setup / preconditions

- **Device key/seed:** a fixed 32-byte seed, e.g. `bytes(range(32))` (Python) or
  the deterministic `(i*17+j)&0xff` fill used by `interop_driver.mjs:60-61`.
  `seed_b64` = base64 of those 32 bytes for the seal input.
- **Seal input JSON** must carry every `_REQUIRED` field (`cli_seal.py:45-53`,
  TS `required` `tn-js.mjs:99-107`): `seed_b64`, `event_type`, `level`,
  `sequence`, `prev_hash`, `timestamp`, `event_id`; `public_fields` optional
  (defaults `{}`). `prev_hash` must be a `sha256:<64 hex>` string.
- **OR a real ceremony + emitted entry:** run `tn init` to mint a ceremony, write
  one entry with `tn.info`, read it back raw, and use that envelope as the verify
  input. No seal input JSON is needed in this variant.

---

## 4. PASS conditions

For a genuine `seal` output (or real read-raw envelope):

- `verify` returns `{"ok": true, "did", "event_type", "event_id", "row_hash",
  "sequence"}` for every input line.
- `row_hash` recomputed by `verify` (over the public-only fields) equals the
  envelope's stored `row_hash`.
- The Ed25519 signature over `row_hash` verifies against `device_identity`/`did`.
- Process exit code is `0` (per-line results on stdout; no fatal error).
- Same-language: the `seal` stdout fed to `verify` yields all `ok:true`.

---

## 5. FAIL conditions (MUST be caught)

Each of these must produce `ok:false` with the right `reason` (and the malformed
case must exit non-zero), not a false `ok:true`:

| Case | Mutation | Expected |
|------|----------|----------|
| Tampered public field | flip a `public_fields` value after sealing | `ok:false`, `reason:"row_hash mismatch"`, `expected`/`got` present |
| Tampered scalar | change `event_type`/`timestamp`/etc. after sealing | `ok:false`, `reason:"row_hash mismatch"` |
| Bad signature | replace `signature` with a valid-b64 wrong 64 bytes | `ok:false`, `reason:"bad signature"` |
| Broken prev_hash chain | alter `prev_hash` after sealing | `ok:false`, `reason:"row_hash mismatch"` (prev_hash is in the preimage) |
| Encrypted group payload | add a key whose value is `{ciphertext, ...}` | `ok:false`, `reason:"group payload <k> present; public-only verify"` |
| Missing scalar | drop e.g. `signature` | `ok:false`, `reason:"missing signature"` |
| Malformed JSON line | non-JSON on stdin | fatal: stderr + exit `2` (Py `cli_verify.py:147-148`; TS `die` `tn-js.mjs:90-92`) |

Note there is no dedicated "broken prev_hash chain" check as a *chain* concept —
`verify` is per-envelope and `prev_hash` is just a hashed scalar, so a broken
chain surfaces as a `row_hash mismatch`. Cross-envelope chain continuity
(entry N `prev_hash` == entry N-1 `row_hash`) is **not** checked by `verify` and
would need a separate assertion in any round-trip test that wants it.

---

## 6. Current test audit

### Python — `python/tests/test_cli_verify.py`

**Verdict: thorough unit coverage of `verify`, but NOT a seal→verify round-trip.**

- The fixture `_seal(**overrides)` (`test_cli_verify.py:23-56`) **hand-builds and
  re-signs** the envelope inline (`DeviceKey.from_private_bytes` +
  `_compute_row_hash` + `dk.sign`, lines 30-55). It does **not** import or call
  `tn.cli_seal.cmd_seal`. So it reimplements seal's crypto rather than consuming
  seal's output. If `cli_seal.py` drifted from `cli_verify.py`, this test would
  not catch it — both the fixture and `cmd_verify` would move together against the
  same `_compute_row_hash`, but the actual `cmd_seal` envelope renderer
  (key order, compact separators) is never exercised here.
- Coverage is otherwise complete on the verify side:
  - PASS: `test_valid_envelope_ok` (lines 76-89) — `ok:true` shape.
  - FAIL: `test_missing_field` (92), `test_group_payload_rejected` (104) —
    encrypted-group rejection, `test_row_hash_mismatch` (116) — tampered public
    field, `test_bad_signature` (128), `test_per_envelope_exception` (142),
    `test_malformed_json_is_fatal` (158) — exit 2.
  - Plumbing: `test_blank_lines_skipped` (164), `test_default_stdin_fallback` (172).
- Confirmed green: `python -m pytest tests/test_cli_verify.py -q` → **9 passed**.

Gap: tampered *scalar* and broken *prev_hash* are not separately tested (only a
tampered public field), though both reduce to the same `row_hash mismatch` branch.

### TypeScript — `ts-sdk/test/`

**Verdict: NO `.test.ts` covers `verifyCmd` at all. The only seal→verify exercise
is the standalone `interop_driver.mjs`, which is cross-language and out of the CI
run set.**

- There is no `verify`/`seal` `.test.ts` file. `verifyCmd`/`sealCmd` are only
  referenced from `test/interop_driver.mjs` (cross-language harness) and
  `test/tn_py_helper.py` (its Python side).
- `interop_driver.mjs` (`interop_driver.mjs:79-118`) **does** pipe real `seal`
  output into `verify` — but the pairing is cross-language: JS-seal → Py-verify
  and Py-seal → JS-verify (lines 97, 109), plus a same-side seal-byte-equality
  diff (lines 84-93). It never runs JS-seal → JS-verify or Py-seal → Py-verify as
  an assertion. It only checks `ok` truthiness, no FAIL/tamper cases.
- It is **not in `npm test`** — `package.json` exposes it only as
  `test:interop` / `test:all` (`package.json:48-49`), separate from the `test`
  run set (`package.json:46`). `run_set_guard.test.ts` governs `.test.ts` files
  only, so a `.mjs` driver is invisible to it; nothing fails CI if the driver
  rots. So in the default CI path TS `verifyCmd` is **entirely untested**.
- `local_read.test.ts` reads ndjson with fake `row_hash: h${seq}` /
  `signature: s${seq}` (lines 18-19) and never verifies — it is not a verify test.

---

## 7. Gap to a real round-trip test

- **Same-language seal→verify is NOT chained anywhere as a CI assertion.**
  - Python: tested in isolation against a hand-rebuilt fixture; `cmd_seal` is
    never the source of the verified envelope.
  - TypeScript: not tested in CI at all; the only chained seal→verify is the
    out-of-CI, cross-language `interop_driver.mjs`.
- A real same-language round-trip test would: feed seal-input JSON to the
  language's own `seal`, take its **raw stdout**, pipe it to that language's own
  `verify`, assert all `ok:true` with `row_hash`/`sequence` echoed; then mutate
  each line (tampered field, bad sig, group payload, malformed JSON) and assert
  the matching FAIL `reason`/exit code from §5.
- For maximum rigor, replace the seal step with a real `tn.info` write read back
  raw — and verify a genuine `tn init` ceremony log line — so the producer is
  independent of the verify path.

---

## Per-language verdict (summary)

- **Python:** `verify` has complete branch-level unit coverage (9 passing
  tests), but seal→verify is **two isolated steps** — the test re-signs a fixture
  instead of consuming `cmd_seal`'s output. Not a real chained round-trip.
- **TypeScript:** `verifyCmd` has **no `.test.ts` coverage** in the CI run set.
  The only seal→verify chain (`interop_driver.mjs`) is cross-language and runs
  only under `test:interop`, outside `npm test`.
- **Is seal→verify a real chained round-trip?** Not same-language. The single
  genuine seal→verify pipe in the repo is the cross-language interop driver, and
  it is not part of either language's test suite.
