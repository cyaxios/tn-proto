use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::json;
use tn_core::cipher::{btn::BtnPublisherCipher, GroupCipher};
use tn_core::governed::{
    Governance, GovernedDraft, GovernedObject, GovernedReader, GovernedWriter, UseContext,
};
use tn_core::{DeviceKey, Error, Result};

const POLICY: &str = "---\nversion: 1\nschema: tn-agents-policy@v1\n---\n## research.sample\n### instruction\nCreate an aggregate report.\n### use_for\nAggregate research.\n### do_not_use_for\nIndividual disclosure.\n### consequences\nContract review.\n### on_violation_or_error\nRefuse release.\n";

// Count entry into real BTN decryption, including any failed attempt.
struct CountedCipher {
    inner: BtnPublisherCipher,
    decrypts: AtomicUsize,
}
impl CountedCipher {
    fn new() -> Arc<Self> {
        let mut state = tn_btn::PublisherState::setup(tn_btn::Config).unwrap();
        let kit = state.mint().unwrap();
        Arc::new(Self {
            inner: BtnPublisherCipher::from_state(state)
                .with_reader_kit(&kit.to_bytes())
                .unwrap(),
            decrypts: AtomicUsize::new(0),
        })
    }
    fn count(&self) -> usize {
        self.decrypts.load(Ordering::SeqCst)
    }
}
impl GroupCipher for CountedCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.inner.encrypt(plaintext)
    }
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.decrypts.fetch_add(1, Ordering::SeqCst);
        self.inner.decrypt(ciphertext)
    }
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.inner.encrypt_with_aad(plaintext, aad)
    }
    fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.decrypts.fetch_add(1, Ordering::SeqCst);
        self.inner.decrypt_with_aad(ciphertext, aad)
    }
}

struct Fixture {
    object: GovernedObject,
    rules: Arc<CountedCipher>,
    finance: Arc<CountedCipher>,
    identities: Arc<CountedCipher>,
}
impl Fixture {
    fn new() -> Self {
        let device = DeviceKey::generate();
        let rules = CountedCipher::new();
        let finance = CountedCipher::new();
        let identities = CountedCipher::new();
        let policy =
            Governance::from_markdown(device.did(), POLICY, "agents.md", "research.sample")
                .unwrap();
        let object = GovernedWriter::new(&device)
            .with_group("tn.agents", rules.clone(), &[1; 32])
            .unwrap()
            .with_group("finance", finance.clone(), &[2; 32])
            .unwrap()
            .with_group("identities", identities.clone(), &[3; 32])
            .unwrap()
            .seal(
                GovernedDraft::new("research.sample", policy)
                    .unwrap()
                    .group("finance", json!({"amount": 42}))
                    .unwrap()
                    .group("identities", json!({"person": "Alice"}))
                    .unwrap(),
            )
            .unwrap();
        Self {
            object,
            rules,
            finance,
            identities,
        }
    }
    fn reader(&self) -> GovernedReader {
        GovernedReader::new()
            .with_group("tn.agents", self.rules.clone())
            .unwrap()
            .with_group("finance", self.finance.clone())
            .unwrap()
            .with_group("identities", self.identities.clone())
            .unwrap()
    }
    fn assert_business_unopened(&self) {
        assert_eq!(self.finance.count(), 0);
        assert_eq!(self.identities.count(), 0);
    }
}

fn approved_use() -> UseContext {
    UseContext::new("deepvest", "portfolio_analysis", "calculate").unwrap()
}

#[test]
fn use_context_requires_complete_validated_values_even_through_serde() {
    let context = approved_use();
    assert_eq!(context.application(), "deepvest");
    assert_eq!(context.purpose(), "portfolio_analysis");
    assert_eq!(context.operation(), "calculate");
    assert_eq!(
        serde_json::from_value::<UseContext>(serde_json::to_value(&context).unwrap()).unwrap(),
        context
    );
    for (application, purpose, operation) in [
        ("", "portfolio_analysis", "calculate"),
        ("deepvest", "  ", "calculate"),
        ("deepvest", "portfolio_analysis", ""),
        ("deepvest\0other", "portfolio_analysis", "calculate"),
    ] {
        assert!(UseContext::new(application, purpose, operation).is_err());
        assert!(serde_json::from_value::<UseContext>(json!({
            "application": application, "purpose": purpose, "operation": operation
        }))
        .is_err());
    }
    for wire in [
        r#"{"application":"deepvest","operation":"calculate"}"#,
        r#"{"application":"deepvest","purpose":"portfolio_analysis","operation":"calculate","application":"other"}"#,
        r#"{"application":"deepvest","purpose":"portfolio_analysis","operation":"calculate","extra":true}"#,
    ] {
        assert!(serde_json::from_str::<UseContext>(wire).is_err());
    }
}

#[test]
fn refused_and_failed_callbacks_never_decrypt_business_data() {
    let fixture = Fixture::new();
    let reader = fixture.reader();
    assert!(matches!(
        reader.receive_for(
            fixture.object.wire(),
            &approved_use(),
            ["finance"],
            None,
            |_| Ok(false)
        ),
        Err(Error::UseDenied { .. })
    ));
    fixture.assert_business_unopened();
    assert!(matches!(
        reader.receive_for(
            fixture.object.wire(),
            &approved_use(),
            ["finance"],
            None,
            |_| { Err(Error::InvalidConfig("evaluator unavailable".into())) }
        ),
        Err(Error::InvalidConfig(_))
    ));
    fixture.assert_business_unopened();
}

#[test]
fn every_changed_use_component_is_visible_and_refused_before_business_decryption() {
    let fixture = Fixture::new();
    let reader = fixture.reader();
    for use_context in [
        UseContext::new("other", "portfolio_analysis", "calculate").unwrap(),
        UseContext::new("deepvest", "individual_disclosure", "calculate").unwrap(),
        UseContext::new("deepvest", "portfolio_analysis", "export").unwrap(),
    ] {
        assert!(matches!(
            reader.receive_for(
                fixture.object.wire(),
                &use_context,
                ["finance"],
                None,
                |context| {
                    assert_eq!(context.operation(), use_context.operation());
                    Ok(context.use_context() == Some(&approved_use()))
                }
            ),
            Err(Error::UseDenied { .. })
        ));
        fixture.assert_business_unopened();
    }
}

#[test]
fn acceptance_owns_complete_use_and_groups_and_opens_only_selected_group() {
    let fixture = Fixture::new();
    let reader = fixture.reader();
    let mut requested_use = approved_use();
    let mut requested_groups = vec!["finance".to_owned()];
    let admitted = reader
        .governance(&fixture.object)
        .unwrap()
        .accept(requested_use.clone(), &requested_groups, |context| {
            assert_eq!(context.object().id(), fixture.object.id());
            assert_eq!(context.object().writer(), fixture.object.writer());
            assert_eq!(context.policies()?.len(), 1);
            assert!(context.sources()?.is_empty());
            assert_eq!(context.use_context(), Some(&approved_use()));
            assert_eq!(context.groups().unwrap(), ["finance"]);
            fixture.assert_business_unopened();
            Ok(true)
        })
        .unwrap();
    requested_use = UseContext::new("other", "portfolio_analysis", "export").unwrap();
    requested_groups.push("identities".to_owned());
    assert_ne!(admitted.use_context(), Some(&requested_use));
    assert_eq!(admitted.use_context(), Some(&approved_use()));
    assert_eq!(admitted.selected_groups().unwrap(), ["finance"]);
    assert!(reader.open(&admitted, &requested_groups).is_err());
    fixture.assert_business_unopened();
    let opened = reader.open(&admitted, ["finance"]).unwrap();
    assert_eq!(opened.groups()["finance"]["amount"], 42);
    assert_eq!(opened.use_context(), Some(&approved_use()));
    assert_eq!(opened.hidden_groups(), ["identities"]);
    assert_eq!(fixture.finance.count(), 1);
    assert_eq!(fixture.identities.count(), 0);
}

#[test]
fn an_identically_provisioned_foreign_reader_cannot_use_strict_acceptance() {
    let fixture = Fixture::new();
    let reader = fixture.reader();
    let admitted = reader
        .governance(&fixture.object)
        .unwrap()
        .accept(approved_use(), ["finance"], |_| Ok(true))
        .unwrap();
    assert!(fixture.reader().open(&admitted, ["finance"]).is_err());
    fixture.assert_business_unopened();
    assert_eq!(
        reader.open(&admitted, ["finance"]).unwrap().groups()["finance"]["amount"],
        42
    );
}

#[test]
fn changing_reader_material_invalidates_earlier_strict_acceptance() {
    let fixture = Fixture::new();
    let reader = fixture.reader();
    let admitted = reader
        .governance(&fixture.object)
        .unwrap()
        .accept(approved_use(), ["finance"], |_| Ok(true))
        .unwrap();
    let changed_reader = reader
        .with_group("finance", fixture.finance.clone())
        .unwrap();
    assert!(changed_reader.open(&admitted, ["finance"]).is_err());
    fixture.assert_business_unopened();
}

#[test]
fn invalid_selected_groups_fail_before_the_decision_callback() {
    let fixture = Fixture::new();
    let reader = fixture.reader();
    for groups in [
        vec![],
        vec!["finance", "finance"],
        vec!["tn.agents"],
        vec!["missing"],
    ] {
        assert!(reader
            .receive_for(fixture.object.wire(), &approved_use(), groups, None, |_| {
                panic!("invalid groups must be rejected before application admission")
            })
            .is_err());
        fixture.assert_business_unopened();
    }
}

#[test]
fn legacy_admission_remains_explicitly_operation_only_and_cross_reader_compatible() {
    let fixture = Fixture::new();
    let reader = fixture.reader();
    let admitted = reader
        .governance(&fixture.object)
        .unwrap()
        .authorize_with("aggregate", |context| {
            assert_eq!(context.use_context(), None);
            assert_eq!(context.groups(), None);
            Ok(true)
        })
        .unwrap();
    assert_eq!(admitted.use_context(), None);
    assert_eq!(admitted.selected_groups(), None);
    assert_eq!(
        fixture
            .reader()
            .open(&admitted, ["finance"])
            .unwrap()
            .groups()["finance"]["amount"],
        42
    );
}

#[test]
fn native_admission_snapshot_retains_verified_context_after_callback_returns() {
    let fixture = Fixture::new();
    let snapshot = {
        let reader = fixture.reader();
        let mut saved = None;
        reader
            .governance(&fixture.object)
            .unwrap()
            .accept(approved_use(), ["finance"], |context| {
                saved = Some(context.to_owned());
                Ok(true)
            })
            .unwrap();
        saved.unwrap()
    };
    let context = snapshot.context();
    assert_eq!(context.object().id(), fixture.object.id());
    assert_eq!(context.use_context(), Some(&approved_use()));
    assert_eq!(context.groups().unwrap(), ["finance"]);
    assert_eq!(context.policies().unwrap().len(), 1);
    fixture.assert_business_unopened();
}

#[cfg(feature = "fs")]
#[test]
fn configured_objects_pass_the_strict_use_through_receive_and_release() {
    use tn_core::runtime::Objects;
    let objects = Objects::ephemeral(POLICY, "agents.md", &["finance"]).unwrap();
    let source = objects
        .seal(
            objects
                .draft("research.sample")
                .unwrap()
                .group("finance", json!({"amount": 42}))
                .unwrap(),
        )
        .unwrap();
    let mut data = objects
        .receive_for(
            source.wire(),
            &approved_use(),
            ["finance"],
            None,
            |context| {
                Ok(context.use_context() == Some(&approved_use())
                    && context.groups().unwrap() == ["finance"])
            },
        )
        .unwrap();
    let release_use =
        UseContext::new("deepvest", "portfolio_analysis", "release_calculation").unwrap();
    let released = objects
        .release_for(
            &mut data,
            "research.sample",
            &release_use,
            "report-service",
            |context| {
                assert_eq!(context.use_context(), Some(&release_use));
                assert_eq!(context.purpose(), "portfolio_analysis");
                Ok(true)
            },
        )
        .unwrap();
    let governance = objects.reader().unwrap().governance(&released).unwrap();
    assert_eq!(
        governance.governance().fields()["release_context"]["operation"],
        "release_calculation"
    );
    assert_eq!(
        governance.governance().fields()["release_context"]["application"],
        "deepvest"
    );
}
