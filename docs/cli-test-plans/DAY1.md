# Day-1 test matrix — single-user lifecycle (backup / restore / group sync)

Scope: ONE user, their own ceremony. No recipients, no kits, no inbox, no sharing.
The day-1 promise: *I can set up, work, back up, and get everything back on a new machine —
and my groups follow me across my own devices.*

Coverage marks: ✓ have a real test · ◐ partial / mock-only / one language · ✗ gap.
"Must-pass" = the positive round-trip that proves it works. "Must-fail" = the failure modes a correct impl rejects.

| Operation | Must-pass (positive round-trip) | Must-fail (negative) | Multi-device | Cov (py·ts) |
|---|---|---|---|---|
| **init** | scaffolds yaml+keystore+identity; re-init is a no-op (idempotent) | bad profile rejected; existing ceremony not clobbered | — | ✓·✓ |
| **group add** | group lands in authoritative yaml+keystore and is routable (log→read decrypts) | duplicate group; bad cipher; malformed --fields | (see sync) | ◐·✓  (py: no dedicated test) |
| **log write (info/emit)** | entry appended; read-back decrypts same event/level/fields, in order | missing yaml/event → exit 2 | — | ✓·✓ |
| **read / secure_read** | reads own entries; secure_read verifies sig+chain | tampered row_hash / forged sig / broken prev_hash all rejected | — | ✓·✓ |
| **account connect (bind)** | mint code → redeem → account binding + sync-state + global-identity stamp | invalid / expired / replayed code; wrong DID | — | ◐·✓  (py: mock only, no live) |
| **wallet link / status** | link writes linked_vault+project; status shows identity + link + pending queue | link missing args | — | ✓·✓ |
| **backup (wallet sync push)** | body packed (keystore+yaml) → AWK/BEK no-AAD frame → PUT; re-push is idempotent | no passphrase; **stale If-Match conflict** surfaced (not silent overwrite) | concurrent push = conflict | ✓·✓ (py now AWK/BEK) |
| **restore (fresh machine)** | keystore+yaml+groups+log **byte-match** original; restored ceremony reads prior entries AND writes+reads a new one | **wrong passphrase** fails clean (no partial write); **corrupt/partial blob**; missing project | device B restores A's body | ✓·✓  —  **corrupt-blob restore ✗ both** |
| **two-device group sync** | A adds G + sync; B sync → B can **USE** G (encrypt+read); concurrent A=alpha/B=beta → both groups on both | content (`tn.info`) rows still fork under the shared key — out of group-sync scope | group **KEYS merge** via account-inbox snapshot (TS) | ✗·✓  —  **TS done (a5a5e73); Python ✗; content/main-log fork separate** |
| **rotate (single-user)** | rotate group → new epoch kit; ceremony keeps working | rotate unknown group; single-out for multi-recipient rejected | rotate → push → restore keeps new epoch | ◐·◐  —  **rotate→backup→restore round-trip ✗** |
| **mnemonic backup/restore** | `export-mnemonic` shows phrase; **restore-from-mnemonic** reconstructs the same identity/DID | no `--yes` withholds; wrong mnemonic fails | — | ✗·◐  —  **mnemonic restore round-trip ✗ both** |

## The gaps this matrix exposes (day-1, ranked)
1. ~~Two-device group sync has no merge~~ **DONE (TS, a5a5e73)** — group keys now ride the account-inbox snapshot→absorb→install merge path; B can use A's group, concurrent group adds union. Remaining: **Python parity** (same fix in python/tn) and the **content/main-log fork** under the shared device key (concurrent `tn.info` writes — a separate, larger protocol question, deferred by decision).
2. **Corrupt / partial-blob restore untested** (both langs) — what happens if the vault returns a truncated or tampered body? Must fail clean, not write garbage.
3. **Mnemonic backup→restore round-trip untested** (both langs) — the recovery-phrase path (`export-mnemonic` → restore from it) has zero round-trip coverage; only passphrase-restore is proven.
4. **rotate → backup → restore** untested — does a restored ceremony keep the rotated epoch?
5. **Python account-connect is mock-only** — no live redeem (TS has it); and **Python group-add has no dedicated test**.

## Out of day-1 scope (sharing — later)
recipients, kits, `bundle`/`add_recipient`, `inbox accept`, seal-for-recipient, revocation/equivocation, the firehose, web/browser flows.
