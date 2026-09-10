# Secure-default read Task 2 independent review

Verdict: **not ready pending remediation**.

Verification before review: 31 focused Rust tests passed; scoped rustfmt and
diff checks passed.

## Important findings

1. `Runtime::read_with_policy` trusted caller-provided source facts. A caller
   could label a foreign file as the local unsigned/unchained profile. Bind
   active/local/detached/profile/device facts to the selected source inside the
   runtime and test a spoofed context.
2. `secure_read(log_path=foreign)` bypassed the prior validity-aware foreign
   dispatch boundary. Preserve the explicit unsupported error until a
   policy-aware recipient decrypt path exists, and add a foreign BTN regression.
3. Skip scanning used `Storage::read_bytes` and buffered the complete source.
   Add a snapshot streaming interface, track byte offsets incrementally, retain
   only bounded per-line verification state, and prove the streaming path does
   not request the whole source. Materialized accepted result arrays remain
   allowed.

No Critical or Minor findings.
