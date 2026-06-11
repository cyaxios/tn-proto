# `tn absorb` — same-language round-trip test contract

Scope: the `absorb` verb's **same-language** round-trip. An originate verb in
language X produces a `.tnpkg` kit; `absorb` in the **same** language X ingests
it. Python and TypeScript are specified independently (no cross-impl claim is
made here — that lives in `tnpkg_export_absorb.test.ts`).

Handlers under test:

- **Python**: `python/tn/cli.py` — `cmd_bundle` / `cmd_add_recipient` /
  `cmd_absorb` (and the originate primitive `tn.pkg.bundle_for_recipient`,
  `tn.pkg.absorb`).
- **TypeScript**: `ts-sdk/src/cli/bundle.ts` (`bundleCmd`),
  `ts-sdk/src/cli/add_recipient.ts`, `ts-sdk/src/cli/absorb.ts` (`absorbCmd`),
  backed by `NodeRuntime.bundleForRecipient` / `NodeRuntime.absorbPkg`.

---

## 1. Flow

The round-trip is **publisher ceremony → `.tnpkg` artifact → recipient
ceremony**. Two *separate* ceremonies are required because `absorb` installs a
reader kit INTO a ceremony that is not the one that minted it (the verb actively
refuses self-absorb; see §5).

### Python

```
tn init publisher                         # ceremony P (its own DID, keystore)
tn init recipient                         # ceremony R (distinct DID)
# --- originate (run against P) ---
tn add_recipient default <R.did> --out kit.tnpkg
#   └─ cmd_add_recipient → bundle_for_recipient(R.did, kit.tnpkg, groups=["default"])
#      mints a tn.recipient.added event + packs P's group key material as a
#      kit_bundle .tnpkg whose manifest publisher_identity == P.did
# (equivalent originate verb: `tn bundle <R.did> kit.tnpkg [--groups ...]`)
# --- consume (run against R) ---
tn absorb kit.tnpkg --yaml <R/tn.yaml>
#   └─ cmd_absorb: peeks manifest.publisher_identity, rejects if == R.did,
#      else tn.pkg.absorb(kit) installs default.btn.mykit into R's keystore
```

`add_recipient` and `bundle` are two shapes of the same originate primitive
(`bundle_for_recipient`); `add_recipient` takes a single `<group> <did|label>`
and a friendly-label fallback, `bundle` takes `<did> <out> [--groups a,b,c]`.
There is **no separate `compile` verb in the Python CLI** — kit minting happens
inside `bundle_for_recipient`. (The library-level `compile_enrolment` /
`emit_to_outbox` in `tn.compile` is the JWE-cipher enrolment path, a different
originate route used by `test_absorb.py`, not a CLI verb.)

### TypeScript

```
Tn.init(P.yaml)  /  Tn.init(R.yaml)        # two ceremonies, distinct DIDs
# --- originate (run against P) ---
bundleCmd({ recipientIdentity: R.did, out: "kit.tnpkg", groups: "default" })
#   └─ NodeRuntime.bundleForRecipient(R.did, out, { groups })
#   (test harness also uses the equivalent tn.pkg.export({ bundle: { recipientDid, groups }}, out))
# --- consume (run against R) ---
absorbCmd({ packagePath: "kit.tnpkg", yaml: R.yaml })
#   └─ readTnpkg → manifest.fromDid; reject if == R.did; else rt.absorbPkg(pkg)
```

`bundle.ts`/`add_recipient.ts` both delegate to `NodeRuntime.bundleForRecipient`.
There is no standalone `compile.ts` CLI verb (kit minting is inside
`bundleForRecipient`); `--seal-for-recipient` is explicitly unimplemented in the
TS runtime and exits 1.

---

## 2. What it would take to actually work (genuine round-trip)

A real round-trip needs, end to end, all of:

1. **A real publisher ceremony P** with a real device identity (Ed25519 DID) and
   a real `default` group with minted `btn` key material
   (`default.btn.state` + `default.btn.mykit`). Produced by `tn init` /
   `Tn.init`, not by writing keystore files by hand.
2. **A real recipient ceremony R** with its OWN distinct DID and keystore (so
   `R.did != P.did`, otherwise the self-absorb guard fires).
3. **A real kit minted by the real originate verb** — `bundle_for_recipient` /
   `bundleForRecipient` / `tn.pkg.export({bundle})` — NOT a hand-assembled zip.
   The kit must carry: `manifest.publisher_identity` (`fromDid`) == P.did, the
   recipient binding to R.did, and P's group key material for the requested
   groups. A hand-built `Package` + `dump_tnpkg`/`writeTnpkg` proves the absorb
   *parser*, but NOT that the produced-by-originate artifact is absorbable.
4. **A real absorb installing into R** — `tn.pkg.absorb` / `rt.absorbPkg` writing
   `default.btn.mykit` into R's keystore and returning a receipt with
   `kind=kit_bundle`, `accepted_count >= 1`.
5. **A real read-back** — after absorb, R must be able to **decrypt P's entries**
   (`tn read` / `secure_read`). This is the only check that proves the installed
   kit is the *right* key, not just that a file landed. P writes an entry to its
   `default` group; R reads P's log and decrypts.

### Infra gaps / frictions

- **Two ceremonies in one test process.** Both SDKs carry process-global runtime
  state (`tn.init` / `current_config`, the Node runtime singleton). A correct
  test must `init`→act→`flush_and_close`/`close` per ceremony and re-init when it
  switches sides, or run the two sides in subprocesses. The TS test handles this
  with explicit `Tn.init`/`close` per dir; Python CLI tests must mirror it.
- **`tn init` network side effects.** Python `cmd_init` auto-mints a vault
  pending-claim / warm-attach unless `--no-link`. A hermetic round-trip test
  must use `--no-link` (or set up the ceremonies via the library `load_or_create`
  / `Tn.init`) so absorb coverage never depends on a reachable vault.
- **Read-back across two dirs.** To prove decryption, R must read P's *log file*
  (P's `.tn/.../tn.ndjson`) with R's config — the test needs the path to P's log
  and a decrypt assertion, not just a receipt-line regex.
- **`secure_read`**: confirm the verb/name exists in each CLI before asserting on
  it; if absent, the read-back assertion uses `tn read` + a decrypt check at the
  library level (as `test_absorb.py::test_absorb_enrolment_makes_recipient_read`
  does for the JWE path).

---

## 3. Setup / preconditions (enumerated)

1. **Ceremony P (publisher)** — `tn init publisher --no-link` (Python) /
   `Tn.init(P.yaml)` (TS). btn cipher, group `default`. Record `P.did`.
2. **Ceremony R (recipient)** — `tn init recipient --no-link` / `Tn.init(R.yaml)`
   in a *separate* directory. Distinct DID. Record `R.did`. Assert
   `P.did != R.did`.
3. **Real artifact** — run the real originate verb against P:
   - Python: `tn add_recipient default <R.did> --out kit.tnpkg --yaml <P.yaml>`
     (or `tn bundle <R.did> kit.tnpkg --groups default`).
   - TS: `bundleCmd({ recipientIdentity: R.did, out: kit, groups: "default", yaml: P.yaml })`.
   - The kit MUST be the verb's output, not a synthesized zip.
4. **(For read-back)** P writes at least one `default`-group entry
   (`tn info ...` / `tn.info(...)`) and flushes, so R has something to decrypt
   after absorbing.
5. **Env**: `TN_NO_STDOUT=1` to silence envelope echo; `--no-link` / no vault URL
   so no network. Per-ceremony isolated temp dirs. `$TN_YAML` cleared unless the
   discovery branch is the thing under test.

Two ceremonies (publisher + recipient) are mandatory because absorb installs
INTO a different ceremony than the one that minted the kit.

---

## 4. PASS conditions (a correct test asserts ALL)

1. `tn absorb kit.tnpkg` against R exits **0**.
2. Receipt line: `[tn absorb] kind=kit_bundle accepted=<N> skipped=<M>` with
   **`accepted >= 1`** (a real kit installs at least one event/kit).
3. The kit really installs: `<group>.btn.mykit` (e.g. `default.btn.mykit`) now
   exists in **R's keystore** with the bytes from the kit (not R's own self-kit
   bytes). On a clean R that had no prior `default` kit, this is a create; on an
   R with a differing prior kit, the receipt carries `replaced_kit_paths` and the
   WARN block prints (see overwrite below).
4. **Read-back**: after absorb, R can `tn read` P's `default` log and **decrypt**
   the entry P wrote — i.e. the decrypted plaintext is present and contains no
   `$decrypt_error` / `$no_read_key` sentinel. (And/or `secure_read` succeeds if
   that verb exists.) This is the load-bearing proof that the *correct* key
   installed.
5. No stderr on the happy path; stdout matches the receipt-line shape.
6. Idempotent re-absorb of the same kit: second `absorb` exits 0 and reports the
   already-present events as **skipped** (deduped), `accepted` for the
   already-seen events drops to 0.

---

## 5. FAIL conditions (negatives a correct test MUST catch)

1. **Self-absorb refused.** Absorbing a kit whose `publisher_identity`/`fromDid`
   == the active ceremony's DID exits **2** with
   `tn: error: refusing to absorb a package this ceremony minted (from_did=...)`
   and nothing on stdout. (Guard added 0.4.2a9;
   `cli.py::cmd_absorb` / `absorb.ts`.)
2. **`--allow-self-absorb` override.** The same self-minted kit with
   `--allow-self-absorb` / `allowSelfAbsorb: true` exits **0** and installs.
3. **Tampered / bad-signature package.** A `.tnpkg` whose inner body was mutated
   after signing is rejected — library `absorb` returns
   `status=rejected` with `signature` in the reason; the CLI surfaces a rejected
   receipt (no silent accept).
4. **Garbage / non-zip package.** A non-zip `.tnpkg` does NOT crash: the
   manifest peek swallows the parse error and `absorb` produces its own rejected
   receipt — CLI prints `kind=unknown accepted=0 skipped=0`, exit 0 (TS) /
   rejected receipt (Python). The verb must not throw an unhandled exception.
5. **Unsupported kind.** A signed package with an unknown `package_kind` is
   rejected with the kind name echoed in the reason (not stashed, not crashed).
6. **Wrong-recipient kit can't decrypt.** A kit minted for some *other* DID
   (`did:key:zSomeReader`), absorbed into R, must NOT let R decrypt P's entries —
   read-back yields `$decrypt_error` / `$no_read_key` (R is not the bound
   recipient). This is the negative complement of PASS #4.
7. **Overwrite-with-backup.** Absorbing a foreign kit over an existing
   `default.btn.mykit` whose bytes differ overwrites it, the receipt carries
   `replaced_kit_paths`, the verb prints the WARN block, AND the prior bytes are
   preserved at `<name>.previous.<UTC_TS>` in the same dir (data is never lost
   silently).
8. **Missing package / missing explicit yaml** exit **1** with
   `tn: error: package not found:` / `yaml not found:` respectively.

---

## 6. Current test audit

### Python — `python/tests/test_cli_absorb.py`: **DOES NOT EXIST**

No `test_cli_absorb.py` is present. The nearest file is
`python/tests/test_absorb.py` (5 tests, all passing — verified
`pytest tests/test_absorb.py -q` → `5 passed`). It tests the **library** API
`tn.absorb.absorb(cfg, path)`, **not the `tn absorb` CLI verb** (`cmd_absorb`).

Per-test:

- `test_absorb_offer_lands_in_pending_offers` (lines 10–23) — input kit produced
  by the **real** originate path `offer(bob_cfg, publisher_did=...)` (line 14),
  read from `outbox_dir` (line 15). Real artifact. Covers the offer-stash branch,
  not kit_bundle, not the self-absorb guard.
- `test_absorb_rejects_bad_signature` (lines 26–56) — starts from a **real**
  `offer()` artifact (line 39), then **rewrites the zip** to mutate
  `body/package.json` (lines 43–51). This is real-artifact-then-tamper — the
  correct shape for FAIL #3. Covers PASS-negative: tampered → `status=rejected`,
  reason contains `signature`.
- `test_absorb_rejects_unsupported_kind` (lines 59–85) — input is
  **hand-built**: `Package(...)` constructed inline (lines 65–76) + `sign` +
  `dump_tnpkg` (lines 77–80). Synthetic fixture (intentional, for FAIL #5).
- `test_absorb_enrolment_makes_recipient_read` (lines 94–127) — **real
  round-trip at the LIBRARY level** for the JWE enrolment path: Bob mints mykey
  (`_ensure_mykey`), Alice `_add_recipient_jwe_impl` + `compile_enrolment` +
  `emit_to_outbox` (real originate, lines 105–107), Bob `absorb`s (line 109),
  then Alice `tn.info` writes and Bob **reads + decrypts** (lines 113–126). This
  is the read-back proof (PASS #4) — but for the JWE cipher via library calls,
  NOT the btn CLI `add_recipient`/`bundle`→`absorb` chain.
- `test_absorb_accepts_bytes_input` (lines 135–151) — real `offer()` artifact,
  bytes-input variant.

**Python verdict: real round-trip — but at the LIBRARY layer, for the OFFER /
JWE-ENROLMENT paths, NOT the btn CLI verb chain.** There is **zero** coverage of
`cmd_absorb` (the CLI verb): no self-absorb guard, no exit codes, no
`<group>.btn.mykit` install assertion, no `tn add_recipient`/`tn bundle` →
`tn absorb` btn round-trip, no overwrite-WARN, no read-back of a btn kit_bundle.
Relative to *this* contract (the btn CLI round-trip), Python is **coverage-only /
missing** for the CLI verb.

### TypeScript — `ts-sdk/test/cli_absorb.test.ts`: exists (9 tests)

Tests the **real CLI verb** `absorbCmd` directly (line 19 import, called
throughout). The input `.tnpkg` is produced by the **real originate verb**:
`exportKitBundle` calls `tn.pkg.export({ bundle: { recipientDid, groups: ["default"] }}, outPath)`
(lines 59–70) — the same `pkg.export` primitive `bundle.ts` is a thin wrapper
over. **Not hand-built** (except the bad-package case, which writes literal
`"this is not a zip file at all"`, line 171 — intentional for FAIL #4).

Coverage vs the contract:

- **PASS #1/#2** (exit 0, receipt line `kind=kit_bundle accepted=\d+`): covered,
  lines 72–94 (happy: A exports for B.did, B absorbs).
- **FAIL #1** (self-absorb exit 2 + message + nothing on stdout): covered, lines
  96–117.
- **FAIL #2** (`--allow-self-absorb` exit 0): covered, lines 119–137.
- **FAIL #7** (overwrite → replaced-kit WARN block): covered, lines 139–164.
- **FAIL #4** (garbage non-zip → `kind=unknown accepted=0`, no crash): covered,
  lines 166–185.
- **FAIL #8** (package not found exit 1; missing explicit yaml exit 1): covered,
  lines 187–220.
- Discovery branches (`./tn.yaml`, `$TN_YAML`): covered, lines 222–274.

**Not covered** by `cli_absorb.test.ts`:

- **PASS #3** — no assertion that `default.btn.mykit` actually landed in B's
  keystore with the kit's bytes (only the receipt line is matched).
- **PASS #4 / FAIL #6** — **no read-back**: B never reads/decrypts an entry A
  wrote, so the test does not prove the *correct* key installed, and the
  wrong-recipient (`did:key:zSomeReader`) kits in lines 100/122/148 are absorbed
  but their (in)ability to decrypt is never checked.
- **FAIL #3 / #5** (tampered-signature / unsupported-kind) — not exercised at the
  CLI level here (they live in `tnpkg_export_absorb.test.ts` /
  `test_absorb.py`).
- **PASS #6** (idempotent re-absorb / dedup-skip) — not asserted.

**TypeScript verdict: real round-trip (real originate verb → real absorb verb),
strong on the guard/exit-code/overwrite negatives, but stops at the receipt
line — it does NOT verify kit installation on disk or decryption read-back.**

---

## 7. Gap to a real round-trip test

1. **Python has no CLI-verb absorb test at all.** Add `test_cli_absorb.py`
   exercising `cmd_bundle`/`cmd_add_recipient` → `cmd_absorb` for the **btn**
   cipher across two `--no-link` ceremonies: happy install, self-absorb exit 2,
   `--allow-self-absorb` exit 0, package/yaml-not-found exits, overwrite-WARN.
   Today Python only proves the *library* absorb on the offer/JWE paths.
2. **Neither CLI test proves the kit installed.** Add a PASS #3 assertion that
   `<group>.btn.mykit` exists in the recipient keystore post-absorb with the
   kit's bytes (distinct from the recipient's own self-kit).
3. **Neither CLI test proves decryption (the load-bearing check).** Add PASS #4:
   P writes a `default` entry, R absorbs the kit bound to **R.did**, then R
   `read`s P's log and decrypts cleanly — plus the negative FAIL #6: a kit bound
   to a *different* DID absorbed into R yields `$decrypt_error`/`$no_read_key`.
   The TS happy/overwrite tests currently bundle for `did:key:zSomeReader` (a DID
   that is NOT B), so even adding read-back to them as-is would only prove the
   negative; the happy case must bundle for **B.did** (lines 78/228/256 already
   do) and then read back.
4. **No idempotent-re-absorb (dedup) coverage** in either CLI test (PASS #6).
5. **`secure_read`**: confirm whether a `secure_read` CLI verb exists; if so, the
   read-back should assert through it as well as `tn read`.
