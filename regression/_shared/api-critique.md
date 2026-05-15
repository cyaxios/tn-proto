# API critique log

A running log of "does this API surface suck?" findings, recorded
during each silo's implementation. The critic is a side-process: a
read-only sub-agent that looks at the SDK surface a silo exercises
and answers, in plain language, **would a reasonable developer want
to write this code?**

The critic exists because passing tests are necessary but not
sufficient. A silo can have green tests against an API surface that's
miserable to actually use. The critic catches that disconnect.

## When the critic runs

Once per silo PR, after the tests are drafted, before the PR is
opened. Its findings are recorded here, in this file, in append-only
fashion. Patterns that recur across silos (e.g. "every silo's critic
flagged that init returns implicit state") become signal for surface
changes in the SDK itself.

## The critic's brief (template — reuse for every silo)

The critic is given:

- **Silo id + scope**: which use case, what surface is touched.
- **Read access**: the SDK files the silo exercises, plus the silo's
  test code.
- **NO write access**: it doesn't edit tests or SDK; it produces a
  report.

It answers, for each public API the silo exercises:

1. **Discoverability** — How does a user find this verb? Is the name
   what they'd guess? Does the SDK's top-level export list it
   prominently, or hide it behind submodules?
2. **Ergonomics** — Is the call shape natural? Right number of args?
   Reasonable defaults? Does the user have to read source to know
   what's required?
3. **Failure modes** — When it goes wrong, do you get a useful error
   message, or an internal stack trace? Does the error point at what
   the user did wrong?
4. **Type signatures** — Are parameters and returns clear from names
   alone, without docstring spelunking?
5. **Consistency** — Does this verb match conventions used elsewhere
   in the SDK? (Naming, arg order, return shape, error class family.)
6. **"Real world" smell** — Would you write this code in your own
   project? Or is the silo test contrived to dodge sharp edges?
7. **Peer comparison** — How do similar tools in the ecosystem
   handle this? (winston/pino for logging, opentelemetry for
   tracing, etc.) Are we worse, on-par, better?

It records:

- **Findings** — per-API, blocking-or-non-blocking, with examples.
- **Suggested API changes** — what the verb would look like if it
  didn't suck. (Even if we don't act on it now, recording forces us
  to know what good looks like.)
- **Cross-silo patterns** — anything that's likely to recur in other
  silos. The implementer of the next silo reads this and watches for
  the same pattern.

## How findings are addressed

For each finding the implementer decides:

- **Block this PR** — the API is so bad we should fix it before
  pinning regression tests against it. (The test would lock in
  unfortunate UX.) Critic findings classified `blocking` get
  resolved before the silo PR merges.
- **Track + ship** — the surface is awkward but not broken; ship
  the test, file a follow-up issue. Recorded in this file with a
  `[track]` tag.
- **By design** — explicit choice; document the reason. Recorded
  with `[by-design]` tag.

## Findings log

Each entry: ISO date, silo id, critic call summary, findings list.

---

### 2026-05-14 — C3 (TS module-level logging) — pre-test surface walk

**Critic invocation:** before writing C3 tests, the implementer
inspected `ts-sdk/src/index.ts` to find the top-level `info / warning
/ error / debug / log / init / read` exports that C3 was designed to
exercise. Result: those exports **do not exist**.

What `ts-sdk` actually exports at the package surface
(`@tnproto/sdk/index.ts:25-72`):

- `Tn` class (with static `Tn.init(...)` + instance methods `t.info`,
  `t.warning`, …)
- `Entry`, `VerifyError`
- `setLevel`, `getLevel`, `isEnabledFor`, `setSigning`, `setStrict`
  (process-global toggles)
- Error classes (`VerificationError`, `ChainConflictError`, …)
- Types and namespaces

There is **no** `import { info } from "@tnproto/sdk"` path. A TS
developer must instantiate `Tn` to log anything.

**Finding — `[blocking?]` (needs decision):**

The Python SDK has a **module-level singleton-backed surface**
(`tn.info(...)`, `tn.read()`) that uses a process-global runtime
established by `tn.init()`. The TS SDK does NOT mirror this — every
log call requires a `Tn` instance.

This is genuine API drift, not a bug. Two viable directions:

- **(A) Mirror Python on TS**: add top-level `info / warning / error
  / debug / log / read / init / close` exports to `ts-sdk/src/index.ts`,
  backed by a process-global default `Tn` instance. Closes the
  cross-SDK drift and makes the "I just want to log one line in a
  script" path identical on both runtimes.

- **(B) Drop module-level from the plan**: rename C3 to "TS-class
  module-import logging" and merge C4 into it (since there's only one
  surface). Accept that TS users always go through `Tn`.

**Cross-silo implication:**
Until this is resolved, the C3/C4 distinction is fictitious on TS.
Same will apply to any future TS silo that distinguishes "module" vs
"object" surfaces.

**Recommendation:**
(A) is the right long-term move — the Python ergonomics are better,
and the user's stated goal is "vibe coder onboarding," which means the
simplest possible call shape. (A) is also genuinely small: ~30 LOC of
wrappers around a lazy-initialized default instance.

**Action taken: `[FIXED IN THIS PR]`.**

User reaction to the finding: "this is a non-starter, lets fix this
now." Path (A) selected. Added bare module-level wrappers to
`ts-sdk/src/index.ts` backed by a lazy-initialized default `Tn`
instance.

Concrete change (~150 LOC in `ts-sdk/src/index.ts`):
- `init(yamlPath?, opts?)` → returns the underlying `Tn` instance
- `info / warning / error / debug / log(eventType, fieldsOrMsg?,
  fieldsIfMsg?)` → severity-stamped envelopes
- `read(opts?)` → generator over `Entry`
- `close()` / `flush_and_close` (alias) → release singleton
- `usingRust()` / `config()` → matching Python's `tn.using_rust()` /
  `tn.current_config()`
- `setContext / updateContext / clearContext / getContext` → safe to
  call before init (no-op rather than throwing) so app boot code can
  set context unconditionally
- Calling `info` etc. before `init` throws a clear error pointing the
  user at `await tn.init(...)`
- Re-init closes the prior default first; safe re-entry

`Tn` class unchanged — power users who want explicit multi-instance
management still use it.

Empirical verification:
- `npm run typecheck` clean
- `npm test` 282/282 pass (purely additive — `Tn` instance methods
  untouched)
- End-to-end smoke: `await tn.init(yamlPath); tn.info("event", {a:1});
  tn.warning(...); tn.read()` round-trips a real attested envelope
  with fields preserved
- Calling `tn.info` after `tn.close` throws with named error pointing
  at `tn.init`

The C1+C3 regression PR now tests both Python and TS module-level on
matched surfaces. The drift this finding surfaced is closed.

**Cross-silo implication (resolved):**
C3 vs C4 distinction is now meaningful again — C3 exercises the
module-level singleton-backed surface (`tn.info`), C4 exercises the
`Tn` class instance surface (`t.info`). Both code paths exist on both
runtimes; cross-runtime parity is real, not aspirational.

---

### 2026-05-14 — C1 (Python module-level logging) — post-test critique

**Critic invocation:** with C1 tests passing green, ran read-only
ergonomics critique against `python/tn/emit.py`, `python/tn/read.py`,
and the C1 tests. Goal: surface what the tests can't see — would a
developer want to write this code?

**Findings — no blockers. Three `[track]` items:**

1. **`[track]` `tn.log()` naming is ambiguous.** The severity-less
   verb is reachable via `tn.log("event", ...)` and always fires
   regardless of level threshold. The name "log" suggests "generic
   entry point" (like Python's stdlib `logging.log(level, msg)`),
   not "severity-less by design." A developer hitting log-level
   threshold filtering will reach for `tn.log()` thinking it's the
   "always fires" verb without knowing why. Suggested rename
   candidates: `tn.audit()`, `tn.raw()`, `tn.always()`. OR keep the
   name and add a docstring example explaining the contract.

2. **`[track]` `*args` footgun in emit signature.** The signature
   `tn.info(event_type, *args, _sign=None, **fields)` (`emit.py:65`)
   accepts optional positional strings that get joined into a
   `"message"` field. A developer naturally writes
   `tn.info("app.login", user_id, ip)` expecting field values; they
   get `event_type="app.login", message="123 192.168.1.1"` instead.
   Not visible in the IDE tooltip. Recommendations:
   - Add a prominent docstring example showing this behavior, OR
   - Drop `*args` and require explicit `message=...` kwarg, OR
   - Accept the gotcha and document it loudly in the README.

3. **`[track]` C1 test gap — missing positional-args and
   severity-less behavior coverage.** C1 currently doesn't exercise:
   - `tn.info("e", "msg1", "msg2")` produces `message="msg1 msg2"`
     (the `*args` footgun above)
   - `tn.log()` fires when threshold is at "error" (the
     severity-less guarantee)
   - Type-coercion edge cases (None, large ints, nested dicts,
     bytes via b64)
   Adding these is a small follow-up; they're not in the C1 PR.

**Otherwise:** discoverability acceptable (docstring example at top
of `__init__.py`), failure modes are clear (pre-init error names the
fix, handler errors propagate loud), internal consistency is good
(Python `tn.info` shape mirrors stdlib `logging.info` enough to be
familiar). Real-world smell: tests are NOT contrived — the call
shape `tn.init() → tn.info() → tn.read()` is what you'd actually
write in a script.

---

### 2026-05-14 — C3 (TS module-level logging) — post-test critique

**Critic invocation:** with C3 tests passing green AND the bare
module-level surface freshly added (this PR), ran the critic to make
sure the new wrappers don't ship with TS-convention violations or
discoverability gaps.

**Findings — no blockers. Four `[track]` items:**

1. **`[track]` `info` / `warning` / `error` / `debug` / `log` need
   TS overload signatures for discoverability.** Current shape is
   `info(eventType, msgOrFields?, fieldsIfMessage?)` — three calling
   patterns implicit in the union type. A TS dev reading the IDE
   tooltip can't tell which arg shape is valid. Adding overloads
   makes it explicit and costs ~6 lines per verb:
   ```typescript
   info(eventType: string, fields: Record<string, unknown>): EmitReceipt;
   info(eventType: string, message: string, fields?: Record<string, unknown>): EmitReceipt;
   ```
   Apply to all five severity verbs.

2. **`[track]` `tn.init()` error wrapping could be friendlier.** If
   the yaml is malformed or the keystore is missing, the underlying
   `NodeRuntime.init()` error bubbles unchanged. Developer sees a
   NodeRuntime stack trace, not a TN-level message. Wrap at
   `index.ts:200` with `cause` chain:
   ```typescript
   throw new Error(
     `tn.init(${JSON.stringify(yamlPath)}) failed: ${msg}. ` +
     `Check that the yaml file exists and is valid.`,
     { cause: e },
   );
   ```

3. **`[track]` `flush_and_close` snake_case violates TS conventions.**
   The alias exists for Python-parity (`tn.flush_and_close()` works on
   both runtimes). It's the **only** snake_case export in the entire
   module — every other verb is camelCase. Options:
   - Keep the alias but mark it `@deprecated` in the docstring,
     redirecting to `close()`, OR
   - Drop the alias entirely (less Python parity, more TS-idiomatic), OR
   - Accept the inconsistency and add a clear comment.
   Currently has neither deprecation note nor comment.

4. **`[track]` Multi-ceremony users get no help from the module-level
   surface.** `tn.init()` manages a single default; running two
   ceremonies in the same process forces using `Tn` class directly
   (not bad — `Tn.use(name)` is fine — but the module-level surface
   doesn't expose `tn.use(name)` to mirror Python's `tn.use("payments")`
   pattern). Either:
   - Add `tn.use(name)` to the module-level surface (returns a `Tn`
     instance scoped to that ceremony name, NOT the default), OR
   - Document explicitly that the module-level surface is
     single-ceremony only.

**Otherwise:** the bare-export shape is idiomatic (mirrors
`@opentelemetry/api`-style singleton-backed exports), the async-init
pattern is correct (failure mode points at `await tn.init`), and the
lazy-singleton implementation is clean. Tests cover all three
calling patterns AND the pre-init / post-close error gates.

---

### 2026-05-14 — log_query.ts parity correctness (foundation/self-critique)

**Critic invocation:** user pushback on a shortcut I took: when the
`yaml` npm package didn't resolve from outside ts-sdk's node_modules,
I replaced `parseYaml` in `regression/_shared/log_query.ts` with a
hand-rolled line-scanner. Tests still passed, so I moved on.

**Finding `[blocking, fixed]`:** the regression suite's whole purpose is
**parity between Python and TS** — same inputs, same assertions, same
files inspected. Replacing a real yaml parser (Python uses
`yaml.safe_load`) with a hand-rolled line-scanner introduces silent
behavior drift the moment a ceremony yaml uses:

- `&anchor` / `*alias` (yaml references)
- `>` / `|` block scalars (multi-line strings)
- `---` multi-doc files
- Quoted keys (`"logs":` vs `logs:`)
- `#` inside quoted string values (my regex strips it as comment)
- Tab indentation (my scanner only matched `\s+`)

In any of those cases TS would find different log paths than Python,
and tests asserting the same predicate name would inspect different
bytes. Tests pass for the wrong reason — exactly the failure mode the
critic process is supposed to surface.

**Fix:** added `regression/package.json` with `yaml` as a dep, ran
`npm install`. `regression/node_modules/yaml/` is what Node's resolver
hits when log_query.ts imports `yaml`, regardless of where the test
runner was launched from. Restored the real `parseYaml(...)` and
matched Python's `_resolve_ceremony_logs` structural-check sequence
exactly:

1. Non-dict / parse-error → `[]`
2. `logs` must be a non-array dict; if so + `logs.path` is a string,
   append (resolved against yaml's parent)
3. `ceremony` same; if so + `admin_log_location` is a string AND not
   `"main_log"` AND not empty AND no `{` template tokens, append

**Action taken in this PR:** `log_query.ts` uses the real yaml parser
with byte-for-byte parity to Python's `log_query.py`. The
`regression/package.json` declares the dep so `npm install` from
`regression/` provides it.

**Follow-up:** add a cross-language `_resolve_ceremony_logs` parity
test — feed the same yaml (with non-trivial features: anchors, block
scalars, comments) to both Python and TS implementations and assert
identical output. Tracked as a walk-tier item.

---

### 2026-05-14 — Vault auth surface: the crawl rule (CORRECTED)

**Context:** rung 5 of the init-param ladder exercised vault restore.
User correction on auth-path scope (revised from a prior wrong entry
in this log):

- **Passphrase → PBKDF2 → credential key**: REALLY IMPORTANT, not a
  deprecation candidate. Headless servers, devs without passkey
  hardware, etc. — this is a load-bearing auth path.
- **Mnemonic-alone**: FUNCTIONAL — decrypts after you've signed in via
  OAuth/WebAuthn. It's the "backup of backups." Users can hold the
  mnemonic offline as last-resort recovery; on a new machine they OAuth
  in AND type the mnemonic, the mnemonic unwraps the BEK.
- **Legacy DID-challenge JWT**: old, but will probably come back.
  Don't pin against it but don't actively kill it either.
- **Google/OAuth**, **WebAuthn-PRF loopback**: production-funnel paths.
- **Dev-auth `/api/v1/dev/login`**: test infra only.

**The crawl rule (this is the important one):**

For the AUTOMATED regression suite we pick **ONE auth path that
actually exercises the encryption** and run it programmatically. That
gives us continuous proof that the crypto pipeline works end-to-end.
The other auth paths get tested via **Playwright** (for paths that
involve a browser dance — OAuth, WebAuthn loopback) or **manually**
(for paths that are inherently human-driven).

Choosing the automated path: it must (a) be representative — exercise
encrypt+decrypt round-trip — and (b) be drivable without a real
browser. The two candidates are:
- Dev-auth `/api/v1/dev/login` + fetch encrypted blob + decrypt with
  BEK from URL fragment (what rung 5 did).
- Passphrase: programmatically supply a passphrase, derive credential
  key via PBKDF2, unwrap the BEK.

**Decision (this PR):** dev-auth path for the automated crawl. It
proves encryption end-to-end (encrypted blob is fetched, BEK from URL
fragment decrypts it, real keystore comes back) WITHOUT pinning any
user-facing auth flow. Playwright covers OAuth + WebAuthn; manual
coverage handles passphrase-PBKDF2 and mnemonic-recovery scenarios.

**Action for upcoming silos:**

- C7 (key custody default) — automated: dev-auth helper exercises the
  init-upload + claim-URL pipeline. Encryption round-trip verified.
- C8 (restore on new machine) — automated: same dev-auth helper to
  fetch the encrypted blob, decrypt with BEK, restore keys, prove
  chain continues. The OAuth+WebAuthn "real user flow" gets its own
  Playwright silo later (probably a walk-tier item).
- Passphrase + mnemonic restore — manual / Playwright, NOT in
  automated crawl. They are SUPPORTED PATHS; we just don't drive them
  every CI run.

**Reverts:** the earlier "deprecation candidate" tagging on passphrase
and mnemonic was wrong. Strike from the open follow-ups list.

---

## Open cross-silo follow-up items

Tracked here so future PRs pick them up:

- **C1/C3 #1**: `tn.log()` discoverability (Python + TS)
- **C1 #2**: `*args` footgun in Python emit signature
- **C1 #3**: test coverage gaps (positional args, severity-less log,
  type coercion edge cases)
- **C3 #1**: TS overload signatures for the severity verbs
- **C3 #2**: TS `tn.init()` error wrapping
- **C3 #3**: `flush_and_close` snake_case inconsistency
- **C3 #4**: Multi-ceremony `tn.use(name)` on TS module-level
- **Foundation #1**: Add a cross-language parity test for
  `_resolve_ceremony_logs` — feed the same yaml with non-trivial
  features (anchors, block scalars, comments, quoted keys) to both
  Python and TS impls, assert identical output. Goes in walk tier.
- **Walk #1**: Playwright silo for the OAuth + WebAuthn loopback
  restore flow (the "real user multi-device" scenario). Lives
  alongside the automated dev-auth-driven C8 in walk tier.
- **Manual #1**: Passphrase-PBKDF2 restore path. Document the
  manual test script in walk-tier README; not automated in CI.
- **Manual #2**: Mnemonic-as-backup-of-backups recovery (OAuth +
  type-the-mnemonic) — document, not automated.

---


## 2026-05-14 — C7 silo critic pass

Surface touched: `tn.init(link=True)`, the sync_state pending-claim
record (`tn.sync_state.get_pending_claim`), the auto-link path
(`python/tn/__init__.py:_auto_link_after_init`), claim-URL spec
(`<vault>/claim/<ulid>#k=<b64>`), and the vault routes
(`POST /api/v1/pending-claims`, `GET /api/v1/pending-claims/{id}`,
`POST /api/v1/dev/login`).

### [track] C7 #1 — `_link_done_this_process` is a hidden module global

`python/tn/__init__.py:_auto_link_after_init` uses a module-level
`global _link_done_this_process` flag to guard against the auto-link
banner firing twice in a single Python process. That's the right
intent for end users (no double-banner spam), but the implementation
makes every test that exercises auto-link in a session require explicit
reset — discovered the hard way: tests 2+ in a session silently skipped
the upload entirely with no warning. Failure mode reads "no
claim_url.txt on disk" rather than "auto-link already fired."

Workaround landed in `regression/_shared/fixtures.py:hermetic_machine`
(setattr the flag to False on setup + teardown). That's load-bearing
test infrastructure for the C7/C8 silos.

Better surface options:
- Expose `tn._reset_link_state()` as a test-only public helper (similar
  to `tn.flush_and_close`) so the regression suite isn't reaching into
  a private module attribute.
- Tie the flag to the runtime singleton instead of a module global, so
  `tn.flush_and_close()` resets it automatically.
- Surface a structured warning when auto-link is skipped because the
  flag is already set, instead of returning silently — so a test that
  expects auto-link gets a visible signal that something is wrong.

Non-blocking for the silo (tests work with the fixture workaround) but
this is a real footgun for anyone running tn.init() in a long-lived
process (e.g. a Jupyter kernel that re-inits after a yaml move). They
won't see a re-issued claim URL until they restart the kernel.

### [by-design] C7 #2 — Dev-auth `/api/v1/dev/login` echo-back of `passphrase`

`/api/v1/dev/login` echoes the seeded passphrase in plain text in the
response. The route is gated by `TN_DEV_AUTH_BYPASS=1` and the docstring
calls this out as intentional ("returned so a test runner can drive
the passphrase claim flow without out-of-band coordination"). Verified
fail-fast guard in `app.py:413-415` that refuses to mount this route
when `VAULT_PUBLIC_HOSTNAME` looks non-local. Sufficient guardrail; no
action needed.

### [track] C7 #3 — Claim URL file location is convention, not config

`<yaml_dir>/.tn/sync/claim_url.txt` is hard-coded in
`python/tn/handlers/vault_push.py:_write_claim_url_to_disk`. A user who
keeps their ceremony under e.g. a Dropbox folder might want to opt out
of leaking the URL into a synced directory. Add `TN_NO_CLAIM_URL_FILE=1`
env or a yaml setting. Not blocking — the file is the same shape as
banner output (already on stdout), so leakage exposure is unchanged.

### [track] C7 #4 — `parse_claim_url` lives in the regression suite, not the SDK

`regression/_shared/vault_test_helpers.py:parse_claim_url` parses
`<vault>/claim/<ulid>#k=<b64url>`. A user who wants to claim a URL
programmatically (write a tool that consumes the URL their CI just
printed) has to re-implement this. Lift to `tn.claim_url.parse` /
`tn.claim_url.build` so the SDK owns the spec and the regression suite
is just a consumer.

### Status

All 4 C7 tests green locally against a real subprocess +
mongo:7. The vault end-to-end (mint ceremony → encrypt keystore →
POST → mongo row → dev-auth login → GET → bytes match) is now
gated. Idempotency, URL format, and offline-init are independently
gated.

## 2026-05-14 — Vault execution model (ephemeral vs live)

The C7/C8 silos boot vaults two ways:

* **Live mode (default)**: drives the running `:8790` vault. Real
  mongo (`tn_vault` db), real blob dir, real wire. The `vault_cleanup`
  fixture DELETEs each test-created pending_claim on test exit so the
  live DB stays at the same count before and after a run. Verified:
  12 pending_claims before, 12 after, full 13-test python suite.

* **Ephemeral mode** (`TN_REGRESSION_USE_EPHEMERAL_VAULT=1`): spawn a
  fresh `python -m src` subprocess against an ephemeral mongo DB +
  blob dir. Teardown drops both. Used for CI runners that don't have
  a vault running.

Both modes pass the same 6 vault-touching tests. Differences:

* **Speed**: live ~5-6s; ephemeral ~12-13s (subprocess boot is the
  bulk of the gap).
* **Isolation**: ephemeral starts each session with a virgin mongo DB
  — useful if a future test depends on "exactly 0 prior rows"
  shape. Live starts with whatever the developer has left over;
  vault_cleanup keeps that bounded but doesn't reset.
* **Coverage**: live exercises the production-shaped startup path
  (config loading, index migrations on a live DB); ephemeral
  exercises cold-start (fresh index creation, first-time blob dir).
  Both are valuable.

The default flip (was: ephemeral by default; now: live by default)
matches the developer's framing: "we have the vault running, why
spawn another?". Ephemeral stays as the CI fallback.

---

## 2026-05-14 — C2 silo critic pass

Surface touched: `tn.use(name)` (multi-ceremony handles), `TN.info`
/ `.warning` / `.error` / `.debug` / `.log` / `.read` methods, default
ceremony bridge.

### [by-design] C2 #1 — Default handle and module-level share state

The contract from `_handle.py` line 119-126: the default ceremony's
runtime IS the module-level singleton, while named ceremonies own
independent per-instance runtimes. The C2 default-bridge test gates
this. It's a deliberate asymmetry (avoid breaking `tn.info` users who
also reach for `tn.use("default")`) and the test makes the contract
visible. No action needed; surface the design choice in user-facing
docs so a "why does `tn.use('default')` behave differently?" question
has a documented answer.

### [track] C2 #2 — `t.read()` doesn't take a `where` kwarg

Python's `tn.read()` module-level form accepts kwargs (`where`,
`verify`, etc.); the handle's `t.read()` forwards positionally but
silently ignores the same kwarg shape because it routes through
`self._activate()` which rebinds the singleton. Tested by accident:
`list(t.read())` works, but `list(t.read(where={...}))` quietly
returns everything. Not blocking the silo (we iterate + filter
client-side) but a real footgun.

### Status

4/4 green in <1.5s. No vault contact. Multi-ceremony isolation
(Bug #1) is regressed-against, default-bridge contract is gated.

---

## 2026-05-14 — C4 silo critic pass

Surface touched: `Tn.use(name)`, `Tn.init(yamlPath)`, instance method
verbs, the TS Tn instance accessors.

### [blocking-fixed] C4 #1 — TS `Tn` was missing `name`, `yamlPath`, `isDefault` getters

Python's `TN` exposes `.name`, `.yaml_path`, `.is_default` as documented
properties. TS's `Tn` exposed `did`, `logPath`, `config()`, `usingRust()`
— but none of the parity-named accessors. A maintainer reading the
parity doc would think they're there.

Fix landed in `ts-sdk/src/tn.ts`: added `get name()`, `get yamlPath()`,
`get isDefault()`. The values come from `_rt.config.yamlPath` (already
present); `name` derives from the path regex
`<...>/.tn/<NAME>/tn.yaml`. Net 18 LOC, no breaking change.

This is the second TS-vs-Python parity gap the critic process has
caught — the first was the missing module-level bare exports
(`tn.info`, `tn.read`, etc.) in C3. Pattern: TS-side surface evolves
faster than the parity doc, and parity-rigor only surfaces when a
silo test tries to use a property cross-language. The check_parity.py
tool checks names exist in either index.ts or __init__.py, but it
doesn't check class-method-level parity. Adding that check is a
follow-up.

### [track] C4 #2 — TS `LogQuery` returns an `Envelope` with `.get(key)`, Python returns a dict

Mid-silo I tried `(env as { level?: string }).level` against the
TS LogQuery return — undefined. The TS `Envelope` exposes fields
via `.get(key)` (uniform unknown-typed accessor). Python's
LogQuery returns a plain dict where you write `env.get("level")`.
The verbs look the same but the underlying shape differs.

Not blocking — the test uses `env.get("level")` which works on both
sides. But the parity is shallow: TS's `Envelope` class has typed
getters for some fields (`sequence`, `rowHash`) and the generic
`.get(key)` for everything else, while Python is untyped throughout.

### [track] C4 #3 — TS has no hermetic_machine equivalent

Python tests redirect `TN_IDENTITY_DIR` to a tmpdir + chdir + reset
the `_link_done_this_process` flag. TS tests use `mkdtempSync` +
`process.chdir(td)` and rely on per-process state (no cross-test
identity dir to redirect). For the C4 silo this is fine — the
ts-sdk doesn't have a `~/AppData/Roaming/tn/identity.json`
equivalent. But if the TS SDK ever grows a user-home cache (e.g. for
linked vault state), the regression suite will need a TS hermetic
fixture.

### Status

3/3 green in <1s. The Tn parity gap was a blocking find that the
silo wouldn't have surfaced without the regression rigor. Worth the
trip.

## 2026-05-14 — C7 TS critic pass (SDK gap)

### [blocking-track] C7 TS #1 — TS SDK has no vault auto-backup

`TnInitOptions` is `{ stdout?: boolean }` — no `link` flag. Compared
to Python's `tn.init(link=True)` which fires the full init-upload
chain (`vault_push.py:init_upload`, claim URL write to disk, sync_state
stamp, admin event), TS has none of:

* `link?: boolean` on `TnInitOptions` or `Tn.init` factory.
* A `vaultPush` handler in `handlers/index.ts`.
* A `tn.sync_state.{set,get}_pending_claim` equivalent.
* A `claim_url.txt` persistence convention.
* A `_display_claim_url` parity with Python's.

Consequence: the load-bearing "free-tier funnel" pitch ("pip install,
run it, keys are safe in the cloud") only works on Python today. A
pure-TS Node consumer can't drive the auto-backup flow through the
SDK without re-implementing the entire init-upload path.

`regression/crawl/c7_key_custody_default/c7_ts_sdk_gap.test.ts` is
a placeholder test that's `skip: true` and documents what the test
SHOULD do when the feature lands. The silo's report still counts it
as a tracked gap rather than silent omission.

Cross-language coverage is non-zero: the C8 silo's
`cross_language_restore.test.ts` proves Python A → TS B restore
works end-to-end (DID matches, signing works, verify passes).
That establishes the wire format / zip layout / decrypt pipeline is
language-agnostic — so once TS gets the init-upload write side,
restore on TS B will keep working without further test changes.

Estimated lift to close the gap: port `python/tn/handlers/vault_push.py`
(~600 LOC of Python) to TS. Most of the surface is HTTP + AES-GCM
+ JSON, which Node already has natively. Should be a focused PR
(not in this crawl tier).

## 2026-05-14 — C8 TS cross-language critic pass

Surface touched: cross-language restore. Python machine A (real SDK
auto-link) → TS machine B (helper-driven decrypt + lay-out + `Tn.init`).

### [by-design] C8 TS #1 — TS B doesn't need an SDK-side restore verb

The Python side has `tn.wallet.restore` and friends, but the actual
operation (decrypt + write files + Tn.init) is so simple
(~30 LOC in `_shared/vault_test_helpers.ts:restoreKeystoreTo`) that
the SDK doesn't need to wrap it. A future `Tn.absorbBootstrap(bytes,
{ bek })` helper could land if the use case grows beyond test fixtures,
but it's not blocking — the user-facing flow (browser claim page)
already does this in JS.

### [track] C8 TS #2 — STORED-zip parser is hand-rolled

`_shared/vault_test_helpers.ts:parseStoredZip` is ~40 LOC of zip-
format parsing. The TS SDK has `parseTnpkg` (via `fflate`) which
handles real zip parsing properly. The test helper's parser only
supports the STORED entries the vault emits today; if the format
ever switches to DEFLATE we'd need to thread it through (the
helper handles compression method 8 via `zlib.inflateRawSync` as
a future-proof, but the SDK's parser is the right tool).

Recommend: switch the helper to import `parseTnpkg` from the SDK
when the bootstrap-absorb helper lands. Keep the hand-rolled parser
as a documentation-of-the-format reference.

### Status

2/2 cross-language tests green:
  - Python A → TS B: same DID after restore.
  - TS B can sign a new entry that verifies under `tn.read({verify:
    true})`.

End-to-end runtime: ~3s per test (most is Python subprocess boot
+ vault HTTP round-trips). Vault stays clean across runs.

## 2026-05-14 — C6 silo critic pass

Surface touched: `python -m tn.cli {init, add_recipient, rotate, read}`
plus the negative-path (unknown verb, missing positional, missing
yaml). All tests use a `subprocess.run([sys.executable, "-m",
"tn.cli", ...])` wrapper in the silo's conftest.

### [blocking-track] C6 #1 — CLI ignores `TN_NO_LINK=1` env

`tn init` honors `--no-link` (an explicit flag) but does NOT honor
`TN_NO_LINK=1` from the environment. The library-tier
`_auto_link_after_init` checks the env at call time and short-circuits;
the CLI's `cmd_init` has its own auto-link block (line ~209 of
`cli.py`) that reads only the explicit flag.

Concrete failure: a test runner that exports `TN_NO_LINK=1` and runs
`tn init` ends up POSTing a real pending_claim to
`https://vault.tn-proto.org` (the production vault). Caught during
the C6 init test — we now pass `--no-link` explicitly as a workaround.

Fix: at the top of `cmd_init`, treat `TN_NO_LINK=1` as equivalent
to `--no-link`. Same one-liner the library path uses:

    if os.environ.get("TN_NO_LINK", "").strip() == "1":
        args.no_link = True

Non-blocking for the silo (the `--no-link` flag works), but a real
hermetic-environment surprise for anyone who expects the env to apply
uniformly across the library and CLI surfaces.

### [track] C6 #2 — `tn init` uses legacy `.tn/tn/` layout

`tn init <project>` writes the keystore under `.tn/tn/keys/`, NOT
`.tn/default/keys/` (the newer multi-ceremony layout that
`migrateLegacyLayout` in ts-sdk/src/multi.ts converts FROM). The CLI
hasn't been migrated to the new layout yet. The silo test accepts
both candidate paths so it survives the eventual migration; the
critic flags it for follow-up so the migration actually happens.

### [by-design] C6 #3 — Friendly recipient labels normalize to `did:key:zLabel-...`

`tn add_recipient default alice_test_label` accepts a label and
auto-prefixes it with `did:key:zLabel-` per the CLI help. The test
asserts the admin event has *some* `did:key:` recipient_did; the
exact normalization is a CLI ergonomics decision, not a protocol
contract.

### Status

6/6 green in 7.32s. Tests run in <2s each. Vault counts unchanged
(thanks to `--no-link`).

## 2026-05-14 — C5 TS silo critic pass

### [blocking] C5 TS #1 — TS revoke+rotate does NOT lock out a revoked recipient

Python's `test_revoke_locks_out_recipient.py` passes: Carol (revoked +
rotate) cannot decrypt post-revoke entries. The TS analogue
`ts_revoke_locks_out_recipient.test.ts` fails in two distinct shapes:

A. **Without close+reopen between rotate and post-revoke emit**:
   `alice.info()` on the same open Tn instance after
   `alice.admin.rotate("default")` writes under the pre-rotate epoch
   keys. Carol's revoked kit decrypts the "post-revoke" entry
   cleanly. Security hole.

B. **With close+reopen** (await alice.close(); Tn.use again): the
   re-opened publisher fails INSIDE the wasm self-receipt verification:

       btn error: reader kit is not entitled to decrypt this ciphertext.
       Possible causes: (a) the reader was revoked before this
       ciphertext was produced; (b) the ciphertext was produced by a
       different publisher (check publisher_id match); (c) the
       ciphertext was produced in a different epoch than the kit.

   So `rotateGroup` left the keystore in a state where a fresh open
   can encrypt under epoch N+1 but the receipt-loopback verify
   (using kits also bumped to N+1) doesn't match the ciphertext's
   epoch metadata.

Both failure shapes point at the same root cause: TS rotate doesn't
propagate the new epoch through both the encryption path and the
receipt-verify path consistently. Python's parity passes, so the wire
format is right; the bug is in the TS in-memory rotation handoff.

**Fix sites** (likely):
- `ts-sdk/src/runtime/node_runtime.ts:rotateGroup` — must rebuild the
  publisher's BtnPublisher state in-process after the new self-kit
  lands. Currently it appears to write to disk but not rebind.
- The wasm BTN rotation pipeline in `crypto/tn-btn/src` — receipt-
  loopback verify must use the same epoch the ciphertext was emitted
  under.

**Test status**: `ts_revoke_locks_out_recipient.test.ts` is marked
`{ skip: "BUG: ..." }` so the silo is green while the bug is open.
When fixed, remove the skip and re-run.

**Cross-language consequence**: a Python publisher that rotates,
then hands kits to TS readers, will still work (Python's rotate is
sound + the wire format is symmetric). A TS publisher that needs to
rotate to evict a recipient — the load-bearing browser-side
revocation case — does NOT work today.

**RESOLVED 2026-05-14**:

Root cause: two bugs stacked on each other, and either alone hid the
other. (1) `NodeRuntime.rotateGroup` swapped the on-disk btn state +
TS-side `publishers` map but never tore down the cached `WasmRuntime`
companion. Emit goes through wasm (`_emitViaWasm` → `WasmRuntime.emit`)
and wasm's btn cipher is loaded ONCE at attach time and held in
memory; it has no reload API. So after `admin.rotate("default")`, the
next `info(...)` call kept encrypting under the pre-rotation publisher
seed — Carol's old kit could still unwrap "post-revoke" entries
(failure shape A). (2) After tearing down wasm so the next attach
reloads from disk, the `lastEmitReceipt` shim's `wasm.readRaw()` call
walked the full log including pre-rotation entries; tn-core's
`BtnReaderCipher::decrypt` was returning `Error::Btn(tn_btn::Error::
NotEntitled)` when no kit in its chain decrypted, but `runtime::
read_from` only matched the upper-layer `Error::NotEntitled { .. }`
variant — so the wrapped variant tripped the "return Err(e)" arm and
the whole read aborted (failure shape B). Python doesn't hit either:
its rotate replaces `cfg.groups[group].cipher` in the live logger
(no separate wasm to refresh), and its reader catches
`tn_btn.NotEntitled` directly with no Error wrapper in the way.

Fix: in `rotateGroup`, tear down the cached `WasmRuntime` (close +
null) after the on-disk swap so the next emit re-attaches off the
freshly-rotated keystore; and in `BtnReaderCipher::decrypt`,
normalize the "no kit covered this ciphertext" path to return
`Error::NotEntitled` instead of `Error::Btn(NotEntitled)` so the
read-path skip filter recognizes it.

Files changed:
- `crypto/tn-core/src/cipher/btn.rs` — normalize the multi-kit
  decrypt failure to `Error::NotEntitled` when every kit's failure
  was `tn_btn::Error::NotEntitled`; preserve `Error::Btn(...)` for
  malformed/internal cases.
- `ts-sdk/src/runtime/node_runtime.ts` — add private
  `_resetWasmAfterAdminWrite()` and invoke it inside `rotateGroup`
  after the keystore + yaml swap so the in-flight emit of
  `tn.rotation.completed` (and every subsequent emit on this
  NodeRuntime) lands under the new epoch.
- `regression/crawl/c5_groups_recipients_inproc/ts_revoke_locks_out_recipient.test.ts`
  — removed `{ skip: ... }` and the close+reopen workaround; the
  canonical revoke + rotate + emit flow now runs on a single open
  Tn instance and asserts the documented forward-only contract.

### [track] C5 TS #2 — `bundleForRecipient` double-mints the kit

`addRecipient` mints a kit + writes to disk. `bundleForRecipient`
ALSO mints a fresh kit at bundle time (and emits another
`tn.recipient.added` admin event with a different leaf_index +
kit_sha256). Calling them back-to-back, as the obvious "mint then
bundle" code shape suggests, produces 2 admin events per logical
recipient addition.

Python tests use the same shape (`add_recipient` then
`pkg.export(kind="kit_bundle")`) and Python `add_recipient`
doesn't double-emit, so the pattern only bites on TS. The C5 TS
multi-recipient test ends up with 4 `tn.recipient.added` events for
2 recipients, doubling the admin log noise.

Not security-relevant; functionality-correct. Track as ergonomics.
Either:
- Make `bundleForRecipient` re-use an existing minted kit if one
  exists for the (group, recipient_did) pair, or
- Document that callers should NOT call `addRecipient` if they're
  going to call `bundleForRecipient` next.

### Status

4 pass / 1 skip (the revoke test, blocked on [blocking] #1). The 4
passers establish the BROWSER LOAD-BEARING flow works:
- TS↔TS: Alice mints kit, Frank absorbs + decrypts.
- Py→TS: Python publisher, TS reader decrypts (browser shape).
- TS→Py: TS publisher, Python reader decrypts (cross-platform audit).
- TS multi-recipient: Frank + Bob both decrypt the same envelopes.

## 2026-05-14 — C6 TS silo critic pass

Surface touched: `node bin/tn-js.mjs {admin add-recipient | admin rotate
| read | watch | seal | verify | canonical | info | streams | validate
| compile}`. Compared to Python `tn` CLI (C6 Python critique above).

### [blocking-track] C6 TS #1 — Python and tn-js CLIs use fundamentally different verb shapes

User's framing: "the [CLI] command[s] need to be really similar
otherwise things will get very messy".

Today they aren't:

| Operation       | Python `tn`                        | tn-js                                       |
|-----------------|------------------------------------|---------------------------------------------|
| add recipient   | `tn add_recipient <g> <r>`         | `tn-js admin add-recipient --group <g> --out <kit> --recipient-did <r>` |
| rotate          | `tn rotate [<g>]`                  | `tn-js admin rotate --yaml <p> [--group <g>]` |
| read            | `tn read [<yaml>]`                 | `tn-js read --yaml <path>`                  |
| init            | `tn init <dir>`                    | (none — TS users use `Tn.init()` library)  |
| watch           | `tn watch [<yaml>]`                | `tn-js watch --yaml <path>`                 |

Differences that bite operators:

* **Python uses positionals; tn-js requires --flags.** Muscle memory
  from one CLI fails on the other.
* **Python verb name: `add_recipient` (underscore, top-level).
  tn-js verb path: `admin add-recipient` (admin namespace + hyphen).**
  Three independent differences in one verb.
* **`tn rotate` is top-level on Python; `tn-js admin rotate` is under
  `admin`.** Same drift as add-recipient.
* **No tn-js init verb.** New TS user has to write code; new Python
  user runs `tn init`. The funnel asymmetry is real.

The parity-snapshot test in `ts_cli_verb_parity.test.ts` captures the
current state with named assertions, so any rename forces an
intentional update.

Recommendation: converge on a single shape. Either:
- Python adopts tn-js's `admin <verb>` namespacing + --flag style, OR
- tn-js drops the `admin` prefix and accepts positionals so
  `tn-js add-recipient default did:key:zFrank` is equivalent to
  `tn add_recipient default did:key:zFrank`.

The hyphen-vs-underscore (`add-recipient` vs `add_recipient`) is also
a real ergonomic split — Python's stdlib argparse defaults to
`add_recipient`; Node convention is `add-recipient`. Pick one and
alias the other.

### [track] C6 TS #2 — tn-js has no `init` verb

Python's `tn init <dir>` is the canonical "set up a new project from
the CLI". TS users can only get there via `await Tn.init()` from
code or `Tn.use("default")` (which auto-mints — see the auto-mint
notice in TS C5 test output). For a "we have a CLI, here's how you
get started" tutorial, this asymmetry is awkward.

Lift: a `tn-js init <dir>` verb that mirrors `tn init <dir>` (yaml +
keystore on disk + optional --link). Probably ~50 LOC against the
existing NodeRuntime + admin layer.

### Status

4/4 green:
- `tn-js admin add-recipient` writes a kit + emits the admin event.
- `tn-js read` decodes a log Python's `tn` wrote (cross-CLI proven).
- Unknown verb fails non-zero with non-empty stderr.
- Verb-name parity snapshot pins the current state for future renames.

Vault untouched (no auto-link involvement).
