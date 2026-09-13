//! Compressed labels retain the existing key, ciphertext and lifecycle formats.

use tn_btn::crypto::{aead, kw};
use tn_btn::tree::cover::SubsetLabel;
use tn_btn::{
    subset_key, Ciphertext, Config, CoverEntry, Error, LeafIndex, NodePos, PublisherState,
    ReaderKit,
};

const SEED: [u8; 32] = [0x39; 32];
const BODY: &[u8] = b"compressed broadcast";
const AAD: &[u8] = b"governed-input";

// Fixed CEK and nonce are test vectors only. The production publisher uses OS entropy.
fn seal_labels(state: &PublisherState, labels: &[SubsetLabel]) -> Ciphertext {
    let cek = [0x51; 32];
    let nonce = [0x72; 12];
    let cover = labels
        .iter()
        .map(|label| CoverEntry {
            label: *label,
            wrapped_cek: kw::wrap(&subset_key(&SEED, label), &cek).unwrap(),
        })
        .collect();
    Ciphertext {
        publisher_id: state.publisher_id(),
        epoch: state.epoch(),
        cover,
        body_nonce: nonce,
        body: aead::seal(&cek, &nonce, BODY, AAD).unwrap(),
    }
}

fn contains(node: NodePos, leaf: u64) -> bool {
    let width = 1_u64 << (8 - node.depth);
    (node.index * width..(node.index + 1) * width).contains(&leaf)
}

#[test]
fn existing_serialized_kits_open_arbitrary_descendant_differences() {
    // This bypasses only cover selection: real AES-KW/AEAD and the existing reader
    // establish that longer differences need no new keys or wire representation.
    let mut publisher = PublisherState::setup_with_seed(Config, SEED).unwrap();
    let kits: Vec<_> = (0..256)
        .map(|_| ReaderKit::from_bytes(&publisher.mint().unwrap().to_bytes()).unwrap())
        .collect();
    for (outer, inner) in [
        (NodePos::ROOT, NodePos { depth: 8, index: 7 }),
        (NodePos::ROOT, NodePos { depth: 3, index: 5 }),
        (
            NodePos { depth: 1, index: 1 },
            NodePos {
                depth: 6,
                index: 41,
            },
        ),
    ] {
        let label = SubsetLabel::Difference { outer, inner };
        let ciphertext =
            Ciphertext::from_bytes(&seal_labels(&publisher, &[label]).to_bytes()).unwrap();
        for kit in &kits {
            let opened = kit.decrypt_with_aad(&ciphertext, AAD);
            if contains(outer, kit.leaf().0) && !contains(inner, kit.leaf().0) {
                assert_eq!(
                    opened.unwrap(),
                    BODY,
                    "label {label:?}, leaf {:?}",
                    kit.leaf()
                );
                assert!(matches!(
                    kit.decrypt_with_aad(&ciphertext, b"wrong"),
                    Err(Error::NotEntitled)
                ));
            } else {
                assert!(
                    matches!(opened, Err(Error::NotEntitled)),
                    "label {label:?}, leaf {:?}",
                    kit.leaf()
                );
            }
        }
    }
}

#[test]
fn compressed_publisher_preserves_legacy_history_late_enrollment_and_rotation() {
    let mut publisher = PublisherState::setup_with_seed(Config, SEED).unwrap();
    let survivor = publisher.mint().unwrap();
    let revoked = publisher.mint().unwrap();
    let original_kit = survivor.to_bytes();
    assert_eq!(original_kit.len(), 1881);
    let before_revocation = publisher.encrypt_with_aad(BODY, AAD).unwrap();

    // Retain an old-style eight-entry ciphertext without using today's walker.
    let mut outer = NodePos::ROOT;
    let mut old_labels = Vec::new();
    for depth in 1..=8 {
        let inner = NodePos {
            depth,
            index: revoked.leaf().0 >> (8 - depth),
        };
        old_labels.push(SubsetLabel::Difference { outer, inner });
        outer = inner;
    }
    let legacy = seal_labels(&publisher, &old_labels);
    assert_eq!(legacy.cover.len(), 8);
    publisher.revoke(&revoked).unwrap();
    let compressed = publisher.encrypt_with_aad(BODY, AAD).unwrap();
    assert_eq!(compressed.cover.len(), 1);
    assert_eq!(
        compressed.cover[0].label,
        SubsetLabel::Difference {
            outer: NodePos::ROOT,
            inner: revoked.leaf().as_node(8),
        }
    );
    assert_eq!(compressed.to_bytes().len(), BODY.len() + 132);
    let compressed = Ciphertext::from_bytes(&compressed.to_bytes()).unwrap();
    let legacy = Ciphertext::from_bytes(&legacy.to_bytes()).unwrap();
    let late = publisher.mint().unwrap();
    for kit in [&survivor, &late] {
        assert_eq!(kit.decrypt_with_aad(&compressed, AAD).unwrap(), BODY);
        assert_eq!(kit.decrypt_with_aad(&legacy, AAD).unwrap(), BODY);
        assert_eq!(kit.decrypt_with_aad(&before_revocation, AAD).unwrap(), BODY);
    }
    for ciphertext in [&compressed, &legacy] {
        assert!(matches!(
            revoked.decrypt_with_aad(ciphertext, AAD),
            Err(Error::NotEntitled)
        ));
    }
    assert_eq!(
        revoked.decrypt_with_aad(&before_revocation, AAD).unwrap(),
        BODY
    );
    assert_eq!(survivor.to_bytes(), original_kit);

    let mut rotated = publisher.rotate().unwrap().active;
    let fresh_revoked = rotated.mint().unwrap();
    let fresh_survivor = rotated.mint().unwrap();
    rotated.revoke(&fresh_revoked).unwrap();
    let new_epoch = rotated.encrypt_with_aad(BODY, AAD).unwrap();
    assert_eq!(new_epoch.cover.len(), 1);
    assert_eq!(
        fresh_survivor.decrypt_with_aad(&new_epoch, AAD).unwrap(),
        BODY
    );
    assert!(matches!(
        fresh_revoked.decrypt_with_aad(&new_epoch, AAD),
        Err(Error::NotEntitled)
    ));
    assert!(matches!(
        survivor.decrypt_with_aad(&new_epoch, AAD),
        Err(Error::NotEntitled)
    ));
    assert!(matches!(
        fresh_survivor.decrypt_with_aad(&compressed, AAD),
        Err(Error::NotEntitled)
    ));
    assert_eq!(survivor.decrypt_with_aad(&compressed, AAD).unwrap(), BODY);
}

#[test]
fn compressed_publisher_opens_exactly_survivors_for_h8_patterns() {
    let mut publisher = PublisherState::setup_with_seed(Config, SEED).unwrap();
    let kits: Vec<_> = (0..256).map(|_| publisher.mint().unwrap()).collect();
    let mut patterns: Vec<Vec<u64>> = vec![
        vec![],
        vec![0],
        vec![127],
        vec![255],
        vec![0, 255],
        (0..256).collect(),
        (64..128).collect(),
        (0..256).step_by(2).collect(),
        (0..256).filter(|leaf| *leaf != 17).collect(),
    ];
    // Deterministic, non-cryptographic permutation gives dispersed sets at varied densities.
    for count in [2, 8, 32, 64, 128, 224] {
        patterns.push((0..count).map(|i| (i * 73 + 19) % 256).collect());
    }
    for revoked in patterns {
        let mut state = PublisherState::setup_with_seed(Config, SEED).unwrap();
        for leaf in &revoked {
            state.revoke_by_leaf(LeafIndex(*leaf)).unwrap();
        }
        let ciphertext = state.encrypt_with_aad(BODY, AAD).unwrap();
        if !revoked.is_empty() {
            assert!(ciphertext.cover.len() <= (2 * revoked.len() - 1).min(256 - revoked.len()));
        }
        let ciphertext = Ciphertext::from_bytes(&ciphertext.to_bytes()).unwrap();
        for kit in &kits {
            let opened = kit.decrypt_with_aad(&ciphertext, AAD);
            if revoked.contains(&kit.leaf().0) {
                assert!(
                    matches!(opened, Err(Error::NotEntitled)),
                    "revoked leaf {:?}",
                    kit.leaf()
                );
            } else {
                assert_eq!(opened.unwrap(), BODY, "surviving leaf {:?}", kit.leaf());
            }
        }
    }
}
