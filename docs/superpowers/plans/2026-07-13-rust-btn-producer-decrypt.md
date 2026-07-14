# Rust BTN Producer Decrypt Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a BTN producer decrypt its own ciphertext directly from master state without silently minting or consuming a reader leaf.

**Architecture:** Keep all cryptography and wire parsing inside `tn-btn`. Harden decoded subset labels, share the existing CEK-unwrapping loop between reader and producer paths, then expose two typed `PublisherState` methods. No Rust SDK wrapper is added in this landing; that becomes the next small plan after this capability is reviewed.

**Tech Stack:** Rust 1.85, `tn-btn`, AES-KW, AES-GCM, NNL subset-difference labels.

## Global Constraints

- Do not modify `rust-sdk/src/tn/read.rs`, `seal`, `unseal`, or any runtime adapter.
- Do not change the BTN wire format.
- Producer decrypt must never call `mint` and must leave `issued_count()` unchanged.
- Malformed wire bytes must return `Error::Malformed`; they must not panic during publisher key lookup.
- AAD mismatch remains `Error::NotEntitled`, matching existing BTN behavior.
- Keep each new production function at or below 50 lines.

---

### Task 1: Validate BTN Labels and Add Direct Producer Decrypt

**Files:**
- Modify: `crypto/tn-btn/src/wire.rs:34-45,191-219,438-554`
- Modify: `crypto/tn-btn/src/ciphertext.rs:175-211`
- Modify: `crypto/tn-btn/src/publisher.rs:22-31,291-375`
- Modify: `crypto/tn-btn/tests/six_verbs_tour.rs`

**Interfaces:**
- Consumes: `Ciphertext`, `SubsetLabel`, `ReaderKeyset::try_subset_key`, `PublisherState::subset_key_cached`.
- Produces:
  - `PublisherState::decrypt(&self, ciphertext: &Ciphertext) -> Result<Vec<u8>>`
  - `PublisherState::decrypt_with_aad(&self, ciphertext: &Ciphertext, aad: &[u8]) -> Result<Vec<u8>>`

- [ ] **Step 1: Write failing producer-decrypt tests**

Append to `crypto/tn-btn/tests/six_verbs_tour.rs`:

```rust
#[test]
fn producer_decrypts_without_minting_a_reader() {
    let state = PublisherState::setup(Config).unwrap();
    assert_eq!(state.issued_count(), 0);
    let ciphertext = state.encrypt(b"producer copy").unwrap();

    assert_eq!(state.decrypt(&ciphertext).unwrap(), b"producer copy");
    assert_eq!(state.issued_count(), 0, "decrypt must not consume a leaf");
}

#[test]
fn producer_decrypt_requires_matching_aad() {
    let state = PublisherState::setup(Config).unwrap();
    let ciphertext = state
        .encrypt_with_aad(b"bound body", b"purpose=local")
        .unwrap();

    assert_eq!(
        state
            .decrypt_with_aad(&ciphertext, b"purpose=local")
            .unwrap(),
        b"bound body"
    );
    assert!(matches!(
        state.decrypt_with_aad(&ciphertext, b"purpose=changed"),
        Err(Error::NotEntitled)
    ));
}
```

- [ ] **Step 2: Run the integration test and confirm the expected failure**

Run:

```powershell
$env:CARGO_TARGET_DIR='C:\codex\tn\tn_proto\target'
cargo test -p tn-btn --test six_verbs_tour
```

Expected: compile failure because `PublisherState::decrypt` and `decrypt_with_aad` do not exist.

- [ ] **Step 3: Write a failing hostile-label regression**

Append inside `crypto/tn-btn/src/wire.rs`'s existing `tests` module:

```rust
#[test]
fn malformed_subset_coordinates_are_rejected() {
    use crate::tree::cover::SubsetLabel;

    let cases = [
        SubsetLabel::Difference {
            outer: NodePos { depth: 9, index: 0 },
            inner: NodePos { depth: 10, index: 0 },
        },
        SubsetLabel::Difference {
            outer: NodePos { depth: 1, index: 2 },
            inner: NodePos { depth: 2, index: 4 },
        },
        SubsetLabel::Difference {
            outer: NodePos { depth: 2, index: 1 },
            inner: NodePos { depth: 2, index: 1 },
        },
    ];

    for label in cases {
        let mut writer = Writer::with_capacity(19);
        write_subset_label(&mut writer, &label);
        let bytes = writer.into_vec();
        let mut reader = Reader::new(&bytes, "ciphertext");
        assert!(matches!(
            read_subset_label(&mut reader),
            Err(Error::Malformed { .. })
        ));
    }
}
```

Run:

```powershell
cargo test -p tn-btn wire::tests::malformed_subset_coordinates_are_rejected
```

Expected: assertion failure because invalid coordinates currently deserialize successfully.

- [ ] **Step 4: Validate every decoded subset coordinate**

In `crypto/tn-btn/src/wire.rs`, add:

```rust
use crate::config::TREE_HEIGHT;
use crate::tree::{is_ancestor, LeafIndex, NodePos};
```

Replace `read_node` and `read_subset_label` with:

```rust
fn read_node(r: &mut Reader<'_>) -> Result<NodePos> {
    let node = NodePos {
        depth: r.u8()?,
        index: r.u64()?,
    };
    if node.depth > TREE_HEIGHT || node.index >= (1_u64 << node.depth) {
        return Err(Error::Malformed {
            kind: r.kind,
            reason: format!(
                "invalid tree node depth={} index={} for height {TREE_HEIGHT}",
                node.depth, node.index
            ),
        });
    }
    Ok(node)
}

fn read_subset_label(r: &mut Reader<'_>) -> Result<SubsetLabel> {
    match r.u8()? {
        SUBSET_FULLTREE => Ok(SubsetLabel::FullTree),
        SUBSET_DIFFERENCE => {
            let outer = read_node(r)?;
            let inner = read_node(r)?;
            if outer.depth >= inner.depth || !is_ancestor(outer, inner) {
                return Err(Error::Malformed {
                    kind: r.kind,
                    reason: format!(
                        "subset inner {inner:?} must be a strict descendant of outer {outer:?}"
                    ),
                });
            }
            Ok(SubsetLabel::Difference { outer, inner })
        }
        other => Err(Error::Malformed {
            kind: r.kind,
            reason: format!("unknown subset label tag {other:#x}; expected 0x00 or 0x01"),
        }),
    }
}
```

- [ ] **Step 5: Extract the shared decrypt loop**

Replace `decrypt_with_keyset_with_aad` in `crypto/tn-btn/src/ciphertext.rs` and add the crate-private helper below it:

```rust
pub fn decrypt_with_keyset_with_aad(
    keyset: &ReaderKeyset,
    ct: &Ciphertext,
    aad: &[u8],
) -> Result<Vec<u8>> {
    decrypt_with_resolver(ct, aad, |label| keyset.try_subset_key(label))
}

/// Open a ciphertext with subset keys supplied by `resolve`.
pub(crate) fn decrypt_with_resolver<F>(
    ct: &Ciphertext,
    aad: &[u8],
    mut resolve: F,
) -> Result<Vec<u8>>
where
    F: FnMut(&SubsetLabel) -> Option<Zeroizing<[u8; KEY_LEN]>>,
{
    for entry in &ct.cover {
        let Some(subset_key) = resolve(&entry.label) else {
            continue;
        };
        let Ok(cek) = unwrap(&subset_key, &entry.wrapped_cek) else {
            continue;
        };
        let cek = Zeroizing::new(cek);
        if let Ok(plaintext) = open(&cek, &ct.body_nonce, &ct.body, aad) {
            return Ok(plaintext);
        }
    }
    Err(Error::NotEntitled)
}
```

- [ ] **Step 6: Add the producer methods**

Use this import in `crypto/tn-btn/src/publisher.rs`:

```rust
use crate::ciphertext::{decrypt_with_resolver, Ciphertext, CoverEntry};
```

Add immediately after `PublisherState::encrypt_with_aad`:

```rust
/// Decrypt using publisher master state without minting a reader.
///
/// # Errors
/// Returns [`Error::NotEntitled`] for another publisher or epoch, an empty
/// cover, or failed key/body authentication.
pub fn decrypt(&self, ciphertext: &Ciphertext) -> Result<Vec<u8>> {
    self.decrypt_with_aad(ciphertext, &[])
}

/// Decrypt with byte-identical additional authenticated data.
///
/// # Errors
/// Returns [`Error::NotEntitled`] for another publisher or epoch, an empty
/// cover, failed key/body authentication, or non-matching AAD.
pub fn decrypt_with_aad(&self, ciphertext: &Ciphertext, aad: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.publisher_id != self.publisher_id || ciphertext.epoch != self.epoch {
        return Err(Error::NotEntitled);
    }
    decrypt_with_resolver(ciphertext, aad, |label| {
        Some(self.subset_key_cached(label))
    })
}
```

- [ ] **Step 7: Run the focused verification**

Run:

```powershell
cargo fmt --all -- --check
cargo test -p tn-btn
cargo test -p tn-core --test cipher_btn
cargo clippy -p tn-btn --all-targets -- -D warnings
git diff --check
```

Expected: every command passes; producer decrypt does not change leaf counts; malformed labels fail before key derivation.

- [ ] **Step 8: Commit this landing**

```powershell
git add crypto/tn-btn/src/wire.rs crypto/tn-btn/src/ciphertext.rs crypto/tn-btn/src/publisher.rs crypto/tn-btn/tests/six_verbs_tour.rs
git commit -m "feat(btn): decrypt directly from publisher state"
```

## Completion Gate

- The commit contains only the four listed files.
- `git status --short` is clean.
- No hidden reader kit or leaf is created.
- No wire-format bytes change for valid ciphertexts or kits.
- The next plan may build `tn_proto::btn` entirely from these typed methods and existing codecs.
