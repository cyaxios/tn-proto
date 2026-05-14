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

---

