use std::panic::{self, UnwindSafe};

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, Error as RandError, RngCore};
use tn_bbg::{delegate, keygen, setup, Identity};

struct ZeroThenChaCha {
    zero_bytes_left: usize,
    fallback: ChaCha20Rng,
}

impl ZeroThenChaCha {
    fn for_first_scalar() -> Self {
        Self {
            zero_bytes_left: 64,
            fallback: ChaCha20Rng::seed_from_u64(0x5eed),
        }
    }
}

impl RngCore for ZeroThenChaCha {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let zero_count = dest.len().min(self.zero_bytes_left);
        dest[..zero_count].fill(0);
        self.zero_bytes_left -= zero_count;
        if zero_count < dest.len() {
            self.fallback.fill_bytes(&mut dest[zero_count..]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for ZeroThenChaCha {}

fn assert_panics(f: impl FnOnce() + UnwindSafe) {
    assert!(panic::catch_unwind(f).is_err());
}

#[test]
fn setup_rejects_zero_alpha() {
    let mut rng = ZeroThenChaCha::for_first_scalar();
    assert!(setup(1, &mut rng).is_err());
}

#[test]
fn string_paths_reject_ambiguous_segments() {
    for path in ["", "/reader", "reader/", "reader//policy"] {
        assert_panics(|| {
            let _ = Identity::from_str_path(path);
        });
    }
}

#[test]
fn raw_paths_reject_ambiguous_labels() {
    assert_panics(|| {
        let _ = Identity::from_path(&[b""]);
    });
    assert_panics(|| {
        let _ = Identity::from_path(&[b"reader/policy"]);
    });
    assert_panics(|| {
        let _ = Identity::from_path(&[b"reader\\policy"]);
    });
    assert_panics(|| {
        let _ = Identity::from_path(&[b"."]);
    });
    assert_panics(|| {
        let _ = Identity::from_path(&[b" reader"]);
    });
    assert_panics(|| {
        let _ = Identity::from_path(&[b"reader\npolicy"]);
    });

    let overlong = vec![b'x'; u16::MAX as usize + 1];
    assert_panics(|| {
        let labels: [&[u8]; 1] = [&overlong];
        let _ = Identity::from_path(&labels);
    });
}

#[test]
fn fallible_identity_constructors_report_validation_errors() {
    let id = Identity::try_from_str_path("reader/policy").unwrap();
    assert_eq!(id.depth(), 2);
    assert!(Identity::try_from_str_path("reader//policy").is_err());
    assert!(Identity::try_from_path(&[b"reader", b"policy"]).is_ok());
    assert!(Identity::try_from_path(&[b"reader/policy"]).is_err());
    assert!(Identity::try_from_path(&[b"reader\\policy"]).is_err());
    assert!(Identity::try_from_path(&[b"."]).is_err());
    assert!(Identity::try_from_path(&[b"reader "]).is_err());

    let parent = Identity::try_from_str_path("reader").unwrap();
    assert!(parent.try_child(b"policy").is_ok());
    assert!(parent.try_child(b"policy/epoch").is_err());
}

#[test]
fn delegation_rejects_ambiguous_child_labels() {
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let (pp, msk) = setup(3, &mut rng).unwrap();
    let parent = keygen(
        &pp,
        &msk,
        &Identity::try_from_str_path("reader").unwrap(),
        &mut rng,
    )
    .unwrap();

    assert!(delegate(&pp, &parent, b"", &mut rng).is_err());
    assert!(delegate(&pp, &parent, b"policy/epoch", &mut rng).is_err());
    assert!(delegate(&pp, &parent, b"policy\\epoch", &mut rng).is_err());
    assert!(delegate(&pp, &parent, b"..", &mut rng).is_err());
    assert!(delegate(&pp, &parent, b"policy\n", &mut rng).is_err());

    let overlong = vec![b'x'; u16::MAX as usize + 1];
    assert!(delegate(&pp, &parent, &overlong, &mut rng).is_err());
}
