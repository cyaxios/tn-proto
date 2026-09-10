# Enrollment Task 3 independent review

Verdict: **not ready pending remediation**.

The exact-body indexes, final-byte signing order, strict writers, duplicate and
path checks, signature-before-body ordering, cross-SDK canonical fixtures, and
actual TypeScript absorb migrations were all sound. No Critical or Minor
findings were reported.

## Important findings

1. The public Python no-init bootstrap path used the default-unverified
   `_read_manifest`, parsed `body/tn.yaml`, selected local mutation paths, and
   then re-read the package in verified dispatch. Replace this with a bounded
   manifest-only kind peek followed by one verified package read whose parsed
   bytes are reused for synthetic configuration and dispatch. Trust rejection
   must not fall through to autoinit or create files.
2. Rust's pre-`ZipArchive` scan selected raw EOCD magic without validating the
   comment/end relationship and returned success on malformed candidates; the
   byte path also omitted the early entry-count cap. Validate the real EOCD,
   fail closed on inconsistent metadata, cap entry count and central-directory
   size before `ZipArchive::new`, explicitly handle or reject ZIP64, and test a
   fake later EOCD plus oversized real directory for path and byte inputs.
