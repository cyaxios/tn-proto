# Paper reproducibility review

Reviewed on 2026-09-13. This note separates the supplied paper, its historical experiment artifact, and Python release `2026.9.13b1`. It does not replace the paper or relabel its measurements as results for the current SDK.

## Reviewed material and availability

- Supplied PDF: `TN_Proto__Confidential_and_Verifiable_Objects_for_Governed_Data_Processing.pdf`, SHA-256 `0d0be7e55ba932b4e221cd22fe6673c692e9ac016e30e627a26a25ea144409d3`.
- Separate local experiment artifact: `tn-paper/icissp27`, including `configs/validation.json`, `results/validation-01/`, `native/`, `python/tn_icissp/`, and `tests/`.
- The validation environment pins clean SDK revision `c83a46a57310fcaccc832e50d6dbd75bd477b5b5`, Python extension SHA-256 `8aad86d55761014e17e8fce78c0c1d829f48832685a85a4abc0dabed198d2979`, and benchmark executable SHA-256 `e5d4ce5fb4707d5f8f571e6db0753832549881cb75b15f7bf8697560f933c5c7`. Its summary records raw-data SHA-256 `fec259bd01182ad262112430238942916a4db0883c1e1a085b0a57cf67d2b2f0`.
- Newer local manuscript: `tn-proto-icissp27-revised/main.tex`, SHA-256 `d45525e94437b669f131da6055afeaa1e0ef322fa4aa0203805516a75c807ef3` at review.

The experiment and manuscript names above identify inspected local material. This repository does not claim they are a publicly archived, immutable artifact, and these names are not public download links. A public reproduction package still needs a versioned artifact location, its source manifest, pinned SDK/native installation instructions, configurations, and retained results. An SDK revision alone does not identify every separately maintained experiment source.

## Test counts and executable claims

The paper's Section 7.6 refers to the **experiment harness**, not the whole SDK suite. At its pinned SDK revision, recursive `python/tests/test*.py` source inspection finds 238 files and 1,633 AST functions whose names begin with `test`. Source-function counts, parametrized collected cases, and passing execution results are different quantities. Counts from a later checkout cannot establish the paper harness's size.

The paper harness has five Python files, with 23 test functions expanding to 34 cases:

| Artifact file | Functions | Parametrized cases | Evidence covered |
| --- | ---: | ---: | --- |
| `tests/test_governed.py` | 2 | 7 | Native governed operation sampling, fresh sessions, invalid configurations. |
| `tests/test_governed_conformance.py` | 3 | 3 | Admission, group restrictions, independent sessions, contracts, exact sources, editions, lineage. |
| `tests/test_measurement.py` | 6 | 11 | Percentiles, wall-window throughput, seeded trial bootstrap, invalid inputs. |
| `tests/test_runner.py` | 6 | 6 | Retained trials, failures, overwrite refusal, separate service/queueing summaries. |
| `tests/test_workloads.py` | 6 | 7 | Seeded input, scheduled arrivals, queue counts, failures, workload adapters. |

The controlled-clock test `test_open_loop_includes_wait_from_intended_arrival` asserts queue waits `[0, 10, 20]`, scheduled latencies `[20, 30, 40]`, and a 60-unit elapsed window. Measurement and scheduled-arrival tests therefore exist in the paper artifact. `docs/inspection/python-final.txt` records **34 passed** historically.

The artifact's native integration suite contains **ten named tests in two files**: seven in `native/tests/contracts.rs` and three in `native/tests/row_hash_claims.rs`. The historical log `docs/inspection/native/final-tests.txt` records 7 + 3 passes. Those counts do not describe the entire Rust workspace.

| Claim | Exact artifact source and scope |
| --- | --- |
| Geometry | `contracts.rs::exhaustive_geometry_and_random_coverage` calls the native geometry driver, asserts 65,814 revoked-set cases across heights 0–4 and 1,000 sampled height-eight sets. `native/src/lib.rs` checks label membership independently with leaf intervals: each survivor once, each revoked leaf zero times. These are cases within a test, not 65,814 separately collected tests. |
| Timestamp sensitivity | `row_hash_claims.rs::timestamp_tamper_changes_row_hash` changes only the timestamp and requires unequal row hashes. |
| Sequence exclusion | `sequence_is_absent_from_row_hash_input_but_present_on_wire` exhaustively destructures `RowHashInput`, varies the wire sequence, and checks equal row hashes. |
| Boolean/string equality | `boolean_true_and_string_true_match_the_same_expected_preimage` creates distinct JSON `true` and `"True"` values, then checks both hashes against the same explicit NUL-delimited preimage ending in `x=True`. This demonstrates the general public-value encoder's non-injectivity; it is not a claim that arbitrary JSON types are safe in the governed public domain. |
| Total 35, two contracts, two sources | `examples/governed_workflow.py` and `native/examples/governed_workflow.rs` have corresponding retained outputs in `docs/inspection/python-example.txt` and `docs/inspection/native/example.txt`. |

During this review, the retained prebuilt native test executables were run again and passed all ten tests. A fresh Python run of the measurement, runner, and workload tests excluding the two workload-adapter cases passed **22 tests**. Full historical Python execution was not re-established in that audit environment: its available default TN installation lacked the required governed module. The historical 34-pass log and source inspection must not be described as a new clean rebuild or full fresh pass.

## Reproduction commands and measurement scope

After obtaining the separate artifact and installing its matching native Python package, run from the artifact root. `SDK_ROOT` must point to the pinned historical checkout; `NATIVE_BIN` must identify the benchmark built from that checkout. The recorded hashes are checks on the chosen binaries, not a promise that a new build on another toolchain is byte-identical.

```sh
python scripts/build_native.py --sdk-root "$SDK_ROOT" --output build/paper
python -m pytest -q tests
cargo test --locked --manifest-path build/paper/Cargo.toml -- --test-threads=1
python examples/governed_workflow.py
cargo run --manifest-path build/paper/Cargo.toml --example governed_workflow
python scripts/run.py --config configs/validation.json \
  --output results/paper-run --sdk-root "$SDK_ROOT" --native-bin "$NATIVE_BIN"
```

Set `PYTHONPATH` to the artifact's `python` directory for its application example when the experiment package is not installed. The native executable is `build/paper/target/release/tn-icissp-native`, with `.exe` on Windows. Use a new results directory. The build adapter copies benchmark sources and sets the selected SDK path dependencies; it does not make the whole artifact publicly available or install the pinned Python extension.

The reported validation uses 30 trials, one Windows host, and one workload offered rate. The configured larger rate sweep is not evidence that every rate was measured. Reported p50/p99 figures are means of per-trial quantiles, not pooled percentiles. Native BTN stage timers exclude its wire codec; JWE/HIBE timers include their adapters' codecs. Workload service time, queue wait, scheduled-arrival latency, and successful completions over the elapsed window are separate metrics. These boundaries limit direct comparisons.

## HIBE and JWE assumptions

**HIBE depth four is an experiment setting.** `native/src/lib.rs` calls `tn_hibe::setup(4, ...)` and targets `bench/group`, an identity of depth two. It creates independent reader keys for that same identity. Increasing the experiment's recipient count affects setup, not ciphertext recipient fanout. It does not establish a global runtime maximum of four. The general [HIBE parameter API](../crypto/tn-bbg/src/params.rs) accepts a chosen maximum depth; the existing [Python HIBE initializer](../python/tn/cipher.py) defaults to two, while this release's [FileKeyStore provisioning](../crypto/tn-core/src/providers/file.rs) creates independent depth-one group authorities. The newer local manuscript explicitly calls four the evaluated authority setting; the supplied PDF's wording should be narrowed in a replacement manuscript.

**The JWE length formula is encoder-specific.** Table 5 states sizes before embedding in a TN envelope. For the benchmark's compact General JSON JWE encoder, X25519 `ECDH-ES+A256KW`, `A256GCM`, at least one recipient, and its fixed header layout:

```text
b(k) = ceil(4*k/3)                  # unpadded base64url length
JWE bytes = 125 + 194*s + b(m) + (9 + b(a) if a > 0 else 0)
```

Here `s` is recipient count, `m` plaintext bytes, and `a` caller-AAD bytes. Additional JSON members, different header placement, whitespace, or other JWE modes are outside that formula. The artifact's `native_jwe_and_hibe_wire_formulas` test covers empty-AAD JWE payload residues modulo three and multiple recipient counts, plus the HIBE `m + 234` formula. It is not exhaustive validation of every JWE serialization. The benchmark chooses the last JWE recipient with one private key, so opening includes unsuccessful earlier recipient searches. The [current native JWE implementation](../crypto/tn-core/src/cipher/jwe.rs) and its tests expose the supported encoding and parser behavior.

## Figure, listing, and disclosure

The supplied PDF's Figure 1 shows separate `amounts` and `identity` groups, while Listing 1 uses one `default` business group with an `amounts` field. **The caption already states this distinction.** The listing illustrates working-object behavior; it does not by itself demonstrate separate bank/vendor signing identities or the illustrated missing identity-group key. The [release's bank/vendor example](../python/examples/bank_vendor.py) now supplies that complete boundary, including a vendor result returned to the bank, unavailable identity data, refused marketing use, and retained two-contract/two-source provenance. Its [tests](../python/tests/test_bank_vendor_example.py) provide current release evidence; they do not change the historical listing.

The supplied PDF ends with an empty **Generative AI Disclosure** heading. The newer local LaTeX contains substantive disclosure identifying Codex and Claude assistance and author responsibility. A filled local source does not repair the supplied PDF. The authors should verify that disclosure against actual use, rebuild and inspect the manuscript, and replace or resubmit the appropriate PDF. This review did not modify the old paper.

## What changed in this release

The [governed Python guide](GOVERNED_PYTHON_API.md), [bank/vendor example](../python/examples/bank_vendor.py), and [fifteen enterprise patterns](../python/examples/enterprise/README.md) turn the intended application boundaries into current, inspectable code. Governed receipt decides the use before selected business opening; application calculations, retained contributors, additional contracts, and output approval remain explicit.

The [BTN cover change](BTN_COVER.md) compresses maximal unary paths using the existing labels and key material. A single revoked leaf at height eight changes from eight difference entries to one, reducing ciphertext overhead from 545 to 132 bytes above the payload: **413 bytes saved**. The old 431-byte increase was the difference between one revocation and no revocation (`545 - 114`), not the saving from compression. The [compression tests](../crypto/tn-btn/tests/compressed_cover.rs) exercise current cryptographic behavior and compatibility. These are exact encoding comparisons, not new latency measurements or eightfold speed claims.

The paper's pinned `c83a46...` tables retain the old walker's costs. They must remain historical results unless the authors run and report a separate evaluation of the compressed implementation.
