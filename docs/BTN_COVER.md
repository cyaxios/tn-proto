# BTN subset-difference covers

BTN encrypts a content key to a cover of the group's selected reader leaves. The shipped [configuration](../crypto/tn-btn/src/config.rs) uses a height-eight binary tree with 256 leaves.

The [cover walker](../crypto/tn-btn/src/tree/cover.rs) builds the union of paths from the root to excluded leaves. Starting at an outer node, it follows the sole path child until reaching a branch or excluded leaf. A nonempty path emits `Difference { outer, inner }`, representing all leaves below `outer` except those below `inner`. At a branch, the walker visits both children.

The resulting subsets are nonempty and disjoint. For a tree with `n = 2^h` leaves and `r > 0` distinct excluded leaves, the number of cover entries satisfies:

```text
cover_count <= min(2r - 1, n - r)
```

With every leaf included, the cover is one `FullTree` label. With every leaf excluded, the cover is empty. The walker deduplicates excluded indices and filters indices outside the tree.

## Ciphertext encoding

The [binary encoding](../crypto/tn-btn/src/wire.rs) uses 57 fixed bytes, a 16-byte body authentication tag, a 40-byte wrapped key per entry, and either a 19-byte difference label or a one-byte full-tree label. For `m` plaintext bytes, `cD` difference entries and `cF` full-tree entries:

```text
ciphertext_bytes = m + 73 + 59*cD + 41*cF
```

| Height-eight selection | Cover | Overhead |
| --- | --- | ---: |
| All readers | One full-tree entry | 114 bytes |
| All readers except one leaf | One difference entry | 132 bytes |
| All readers except a non-root aligned subtree | One difference entry | 132 bytes |

The [subset-key implementation](../crypto/tn-btn/src/tree/subset.rs) derives the key for each label. [Reader kits](../crypto/tn-btn/src/reader.rs) hold the material needed to open their cover entries; a serialized height-eight kit occupies 1,881 bytes.

## Tests

Run from the repository root:

```sh
cargo test --locked -p tn-btn
cargo test --locked -p tn-btn --all-features
```

The [cover tests](../crypto/tn-btn/tests/compressed_cover.rs) exercise encryption and decryption with serialized reader kits. Unit tests cover exhaustive small-tree geometry, seeded height-eight selections, and aligned subtrees.
