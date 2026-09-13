# BTN cover compression

The current SDK compresses maximal unary paths in the revoked-leaf Steiner tree. A single revoked leaf in the height-eight tree now requires one difference entry instead of eight. This changes cover selection; the existing ciphertext encoding and subset-key derivation remain in use.

For a complete binary tree of height `h`, let `n = 2^h` and let `r` count unique, valid revoked leaves. The [cover walker](../crypto/tn-btn/src/tree/cover.rs) builds the union of root-to-revoked-leaf paths. Starting at an outer node, it follows the sole Steiner child until reaching a branch or revoked leaf. A nonempty path emits `Difference { outer, inner }`, representing all leaves below `outer` except those below `inner`. At a branch, the walker recurses into both children.

These differences partition the surviving leaves: the emitted label excludes the inner subtree, and recursion covers only that subtree. For `r > 0`, there are `r - 1` branch nodes and at most `2r - 1` possible chain starts. Each emitted subset is nonempty and disjoint, so the label count is bounded by:

```text
cover_count <= min(2r - 1, n - r)
```

With `r = 0`, the cover is one `FullTree` label. With `r = n`, it is empty and no reader can recover the content key from that ciphertext. Duplicate revocations are deduplicated; out-of-range leaf indices are ignored before counting `r`. The shipped [configuration](../crypto/tn-btn/src/config.rs) remains `h = 8`, or 256 leaves.

## Exact byte changes

The [binary encoding](../crypto/tn-btn/src/wire.rs) uses 57 fixed bytes, a 16-byte body authentication tag, a 40-byte wrapped key per entry, and either a 19-byte difference label or a one-byte full-tree label. For `m` plaintext bytes, `cD` difference entries and `cF` full-tree entries:

```text
ciphertext_bytes = m + 73 + 59*cD + 41*cF
```

| Height-eight case | Previous entries | Current entries | Previous overhead | Current overhead |
| --- | ---: | ---: | ---: | ---: |
| No revocations | 1 full-tree | 1 full-tree | 114 bytes | 114 bytes |
| One revoked leaf | 8 difference | 1 difference | 545 bytes | 132 bytes |
| Revoked aligned subtree at depth `d`, `1 <= d <= 8` | `d` difference | 1 difference | `73 + 59*d` bytes | 132 bytes |

For one revoked leaf, compression saves **413 bytes**: `545 - 132`, or seven removed 59-byte entries. **431 bytes** means something different: `545 - 114` was the previous increase from no revocations to one revocation. The current increase is 18 bytes, `132 - 114`. These are exact encoding differences, not claims of eightfold total-size or execution-speed improvement.

## Compatibility and validation

This change preserves existing labels, wire versions, publisher state, [subset-key derivation](../crypto/tn-btn/src/tree/subset.rs), and [reader kits](../crypto/tn-btn/src/reader.rs). A height-eight serialized reader kit remains **1,881 bytes**. No replacement keys are required solely for cover compression. Older eight-entry ciphertexts remain readable by entitled kits; revocation, same-epoch historical access for later enrollment, and rotation retain their existing behavior.

Run from the repository root:

```sh
cargo test -p tn-btn
cargo test -p tn-btn --all-features
```

Each command passed **100 tests scoped to `tn-btn`**: 93 unit tests, three [compression integration tests](../crypto/tn-btn/tests/compressed_cover.rs), and four [existing integration tests](../crypto/tn-btn/tests/six_verbs_tour.rs). The unit suite includes **65,814 revoked-set geometry cases** across heights zero through four; that is a case count, not a test-function count. It also checks all 510 non-root aligned subtrees at height eight and 1,000 seeded height-eight samples across varied revocation densities, plus adversarial patterns. The integration tests exercise real encryption and all 256 minted readers, serialized kits, arbitrary descendant differences, legacy ciphertexts, AAD rejection, revocation, later enrollment, and rotation.

The historical paper experiment pins SDK revision `c83a46a57310fcaccc832e50d6dbd75bd477b5b5` and used the previous uncompressed walker. Its retained tables and measurements remain historical evidence; they are **not benchmarks of this release**. They must not be relabeled as measurements of the compressed implementation.
