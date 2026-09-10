use std::sync::Arc;

use base64::Engine as _;
use serde_json::{json, Value};
use tn_core::cipher::{btn::BtnPublisherCipher, GroupCipher};
use tn_core::governed::{
    Governance, GovernedDraft, GovernedObject, GovernedReader, GovernedWriter, OpenedObject,
    PolicyDag, PolicyRelation, PolicyRevision, PolicyRevisionDraft, POLICY_REVISION_GROUP,
    POLICY_REVISION_TYPE,
};
use tn_core::{DeviceKey, Result};

const POLICY: &str = "---\nversion: 1\nschema: tn-agents-policy@v1\n---\n## research.sample\n### instruction\nCompute the approved aggregate.\n### use_for\nAggregate research.\n### do_not_use_for\nIndividual disclosure.\n### consequences\nContract review.\n### on_violation_or_error\nRefuse release.\n";

fn cipher() -> Arc<dyn GroupCipher> {
    let mut publisher = tn_btn::PublisherState::setup(tn_btn::Config).unwrap();
    let kit = publisher.mint().unwrap();
    Arc::new(
        BtnPublisherCipher::from_state(publisher)
            .with_reader_kit(&kit.to_bytes())
            .unwrap(),
    )
}

struct Fixture {
    device: DeviceKey,
    rules: Arc<dyn GroupCipher>,
    data: Arc<dyn GroupCipher>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            device: DeviceKey::generate(),
            rules: cipher(),
            data: cipher(),
        }
    }

    fn governance(&self) -> Governance {
        Governance::from_markdown(self.device.did(), POLICY, "agents.md", "research.sample")
            .unwrap()
    }

    fn writer(&self) -> GovernedWriter<'_> {
        GovernedWriter::new(&self.device)
            .with_group("tn.agents", self.rules.clone(), &[1; 32])
            .unwrap()
            .with_group(POLICY_REVISION_GROUP, self.data.clone(), &[2; 32])
            .unwrap()
            .with_group("observations", self.data.clone(), &[3; 32])
            .unwrap()
    }

    fn reader(&self) -> GovernedReader {
        GovernedReader::new()
            .with_group("tn.agents", self.rules.clone())
            .unwrap()
            .with_group(POLICY_REVISION_GROUP, self.data.clone())
            .unwrap()
            .with_group("observations", self.data.clone())
            .unwrap()
    }

    fn open(&self, object: &GovernedObject, group: &str) -> OpenedObject {
        let reader = self.reader();
        let view = reader.governance(object).unwrap();
        let admitted = view.authorize("inspect", |_, _| Ok(true)).unwrap();
        reader.open(&admitted, [group]).unwrap()
    }

    fn draft(&self, policy: &str, scope: &str) -> PolicyRevisionDraft {
        PolicyRevisionDraft::from_markdown(
            self.device.did(),
            policy,
            "agents.md",
            "research.sample",
            scope,
        )
        .unwrap()
    }

    fn revision(&self, draft: PolicyRevisionDraft) -> PolicyRevision {
        let sealed = self
            .writer()
            .seal(draft.into_draft(self.governance()).unwrap())
            .unwrap();
        let received = GovernedObject::parse(sealed.wire()).unwrap();
        PolicyRevision::from_opened(&self.open(&received, POLICY_REVISION_GROUP)).unwrap()
    }

    fn rewrite_revision(
        &self,
        revision: &PolicyRevision,
        edit: impl FnOnce(&mut Value),
    ) -> Result<PolicyRevision> {
        let opened = self.open(revision.object(), POLICY_REVISION_GROUP);
        let mut payload = opened.groups()[POLICY_REVISION_GROUP].clone();
        edit(&mut payload);
        let sealed = self.writer().seal(
            GovernedDraft::new(POLICY_REVISION_TYPE, self.governance())?
                .group(POLICY_REVISION_GROUP, payload)?,
        )?;
        PolicyRevision::from_opened(&self.open(&sealed, POLICY_REVISION_GROUP))
    }

    // Produce a correctly encrypted and signed writer declaration. This lets
    // the tests distinguish contract acceptance from ordinary crypto validity.
    fn rewrite_governance(
        &self,
        object: &GovernedObject,
        edit: impl FnOnce(&mut serde_json::Map<String, Value>, &mut Value),
    ) -> GovernedObject {
        use tn_core::chain::{compute_row_hash, GroupInput, RowHashInput};
        use tn_core::sealed_object::{extract_group_blocks, ENVELOPE_RESERVED};
        assert_eq!(object.group_names(), ["tn.agents"]);
        let mut env = object.envelope().clone();
        let mut fields = self
            .reader()
            .governance(object)
            .unwrap()
            .governance()
            .fields()
            .clone();
        let mut aad: Value = serde_json::from_str(env["tn_aad"].as_str().unwrap()).unwrap();
        edit(&mut fields, &mut aad["tn.agents"]);
        let marker = tn_core::canonical::canonical_bytes(&aad["tn.agents"]).unwrap();
        let tokens: serde_json::Map<String, Value> = fields
            .iter()
            .map(|(name, value)| {
                (
                    name.clone(),
                    json!(tn_core::indexing::index_token(&[1; 32], name, value).unwrap()),
                )
            })
            .collect();
        let ciphertext = self
            .rules
            .encrypt_with_aad(
                &tn_core::canonical::canonical_bytes(&json!(fields)).unwrap(),
                &marker,
            )
            .unwrap();
        env["tn.agents"] = json!({
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(ciphertext),
            "field_hashes": tokens,
        });
        env["tn_aad"] =
            json!(String::from_utf8(tn_core::canonical::canonical_bytes(&aad).unwrap()).unwrap());
        let blocks = extract_group_blocks(&env).unwrap();
        let public = env
            .iter()
            .filter(|(name, _)| {
                !ENVELOPE_RESERVED.contains(&name.as_str()) && !blocks.contains_key(*name)
            })
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let groups = blocks
            .into_iter()
            .map(|(name, block)| {
                (
                    name,
                    GroupInput {
                        ciphertext: block.ciphertext,
                        field_hashes: block.field_hashes,
                    },
                )
            })
            .collect();
        let row_hash = compute_row_hash(&RowHashInput {
            device_identity: env["device_identity"].as_str().unwrap(),
            timestamp: env["timestamp"].as_str().unwrap(),
            event_id: env["event_id"].as_str().unwrap(),
            event_type: env["event_type"].as_str().unwrap(),
            level: env["level"].as_str().unwrap(),
            prev_hash: env["prev_hash"].as_str().unwrap(),
            public_fields: &public,
            groups: &groups,
        });
        env["signature"] = json!(tn_core::signing::signature_b64(
            &self.device.sign(row_hash.as_bytes())
        ));
        env["row_hash"] = json!(row_hash);
        GovernedObject::parse(&serde_json::to_string(&env).unwrap()).unwrap()
    }
}

#[test]
fn revision_round_trip_recomputes_normalized_policy_and_retains_signed_source() {
    let f = Fixture::new();
    let policy = POLICY.replace("aggregate.", "aggregate café 🦀.");
    let second_section = policy.split_once("## research.sample").unwrap().1;
    let document = format!("{policy}\n## research.release{second_section}");
    let root = f.revision(f.draft(&document, "research"));
    let expected =
        Governance::from_markdown(f.device.did(), &document, "agents.md", "research.sample")
            .unwrap();
    assert_eq!(root.governance(), &expected);
    assert_eq!(root.writer(), f.device.did());
    assert_eq!(root.scope(), "research");
    assert!(root.parents().is_empty());
    assert_eq!(root.id(), root.object().id());
    let reopened =
        PolicyRevision::from_opened(&f.open(root.object(), POLICY_REVISION_GROUP)).unwrap();
    assert_eq!(reopened.object().wire(), root.object().wire());
    let altered = document.replace("## research.release", "## research.another");
    let other = f.revision(f.draft(&altered, "research"));
    assert_ne!(
        other.governance().policy_ref(),
        root.governance().policy_ref()
    );
    assert!(f
        .rewrite_revision(&root, |body| {
            body["document"]["events"]["research.release"]["instruction"] =
                json!("Changed sibling rules.");
        })
        .is_err());
}

#[test]
fn dag_admits_each_parent_then_selects_an_explicit_revision() {
    let f = Fixture::new();
    let root = f.revision(f.draft(POLICY, "research"));
    let left = f.revision(
        f.draft(&POLICY.replace("version: 1", "version: 2"), "research")
            .parent(root.id(), PolicyRelation::Revise)
            .unwrap(),
    );
    let right = f.revision(
        f.draft(POLICY, "research")
            .parent(root.id(), PolicyRelation::Extend)
            .unwrap(),
    );
    let merged = f.revision(
        f.draft(POLICY, "research")
            .parent(left.id(), PolicyRelation::Combine)
            .unwrap()
            .parent(right.id(), PolicyRelation::Combine)
            .unwrap(),
    );
    let mut dag = PolicyDag::new();
    let mut edges = Vec::new();
    for revision in [&root, &left, &right, &merged] {
        dag.admit(revision.clone(), |candidate, parent| {
            assert_eq!(candidate.writer(), f.device.did());
            if let Some((edge, parent)) = parent {
                assert_eq!(edge.revision_id(), parent.id());
                edges.push(parent.id().to_owned());
            }
            Ok(true)
        })
        .unwrap();
    }
    assert_eq!(edges.len(), 4);
    assert_eq!(dag.len(), 4);
    let selected = dag.select(merged.id(), "research", |_| Ok(true)).unwrap();
    assert_eq!(selected.revision_id(), Some(merged.id()));
    assert_eq!(
        dag.resolve(&selected, "research").unwrap().id(),
        merged.id()
    );
    // Historical selection remains explicit even after later revisions exist.
    assert_eq!(
        dag.select(root.id(), "research", |_| Ok(true))
            .unwrap()
            .revision_id(),
        Some(root.id())
    );
    assert!(dag.select(merged.id(), "another", |_| Ok(true)).is_err());
    assert!(dag.select(merged.id(), "research", |_| Ok(false)).is_err());
    assert!(dag.resolve(&selected, "another").is_err());
    assert!(dag.resolve(&f.governance(), "research").is_err());
}

#[test]
fn update_authority_is_checked_for_every_edge_and_failed_admission_is_atomic() {
    let a = Fixture::new();
    let b = Fixture::new();
    let left = a.revision(a.draft(POLICY, "left"));
    let right = b.revision(b.draft(POLICY, "right"));
    let merged = a.revision(
        a.draft(POLICY, "combined")
            .parent(left.id(), PolicyRelation::Combine)
            .unwrap()
            .parent(right.id(), PolicyRelation::Combine)
            .unwrap(),
    );
    let mut dag = PolicyDag::new();
    assert!(dag.admit(left.clone(), |_, _| Ok(false)).is_err());
    assert!(dag.is_empty());
    dag.admit(left.clone(), |node, parent| {
        Ok(parent.is_none() && node.writer() == a.device.did())
    })
    .unwrap();
    dag.admit(right.clone(), |node, parent| {
        Ok(parent.is_none() && node.writer() == b.device.did())
    })
    .unwrap();
    let mut calls = 0;
    assert!(dag
        .admit(merged.clone(), |candidate, parent| {
            calls += 1;
            Ok(candidate.writer() == parent.unwrap().1.writer())
        })
        .is_err());
    assert_eq!(calls, 2);
    assert_eq!(dag.len(), 2);
    assert!(dag.get(merged.id()).is_none());
    assert!(dag
        .admit(merged.clone(), |_, _| Err(tn_core::Error::InvalidConfig(
            "authority unavailable".into()
        )))
        .is_err());
    assert_eq!(dag.len(), 2);
    // An application can provide explicit authorization spanning both parents.
    dag.admit(merged, |_, _| Ok(true)).unwrap();
    assert_eq!(dag.len(), 3);
}

#[test]
fn parent_first_admission_preserves_acyclic_history_without_forward_references() {
    let f = Fixture::new();
    let root = f.revision(f.draft(POLICY, "research"));
    let child = f.revision(
        f.draft(POLICY, "research")
            .parent(root.id(), PolicyRelation::Revise)
            .unwrap(),
    );
    let mut dag = PolicyDag::new();
    assert!(dag
        .admit(child.clone(), |_, _| panic!(
            "unresolved ancestry must precede authority"
        ))
        .is_err());
    assert!(dag.is_empty());
    dag.admit(root.clone(), |_, _| Ok(true)).unwrap();
    dag.admit(child, |_, _| Ok(true)).unwrap();
    assert!(dag.admit(root, |_, _| Ok(true)).is_err());
    assert_eq!(dag.len(), 2);
    let unresolved = format!("sha256:{}", "0".repeat(64));
    let forward = f.revision(
        f.draft(POLICY, "research")
            .parent(&unresolved, PolicyRelation::Extend)
            .unwrap(),
    );
    assert!(dag.admit(forward, |_, _| Ok(true)).is_err());
    assert_eq!(dag.len(), 2);
}

#[test]
fn typed_revision_rejects_invalid_parents_and_relationship_shapes() {
    let f = Fixture::new();
    let root = f.revision(f.draft(POLICY, "research"));
    assert!(f
        .draft(POLICY, "research")
        .parent("latest", PolicyRelation::Revise)
        .is_err());
    assert!(f
        .draft(POLICY, "research")
        .parent(root.id(), PolicyRelation::Revise)
        .unwrap()
        .parent(root.id(), PolicyRelation::Revise)
        .is_err());
    assert!(f
        .draft(POLICY, "research")
        .parent(root.id(), PolicyRelation::Combine)
        .unwrap()
        .into_draft(f.governance())
        .is_err());
    let other = f.revision(f.draft(POLICY, "another"));
    assert!(f
        .draft(POLICY, "research")
        .parent(root.id(), PolicyRelation::Revise)
        .unwrap()
        .parent(other.id(), PolicyRelation::Extend)
        .unwrap()
        .into_draft(f.governance())
        .is_err());
    assert!(PolicyRevisionDraft::from_markdown(
        f.device.did(),
        POLICY,
        "agents.md",
        "research.sample",
        ""
    )
    .is_err());
}

#[test]
fn signed_revision_payload_is_validated_against_its_policy_document() {
    let f = Fixture::new();
    let root = f.revision(f.draft(POLICY, "research"));
    for field in ["policy", "governed_by", "event_type", "schema"] {
        assert!(
            f.rewrite_revision(&root, |body| body[field] = json!("invalid"))
                .is_err(),
            "{field}"
        );
    }
    assert!(f
        .rewrite_revision(&root, |body| body["scope"] = json!(""))
        .is_err());
    assert!(f
        .rewrite_revision(&root, |body| {
            body["document"]["events"]["research.sample"]["instruction"] =
                json!("Other instruction");
        })
        .is_err());
    assert!(f
        .rewrite_revision(&root, |body| {
            body["document"]["events"]["research.sample"]["extra"] =
                json!("Unaccounted policy field");
        })
        .is_err());
    assert!(f
        .rewrite_revision(&root, |body| body["extra"] = json!(true))
        .is_err());
    assert!(f
        .rewrite_revision(&root, |body| {
            body["parents"] =
                json!([{"revision_id": root.id(), "relation": "supersede_everything"}]);
        })
        .is_err());
    let unrelated = f
        .writer()
        .seal(
            GovernedDraft::new("research.sample", f.governance())
                .unwrap()
                .group(POLICY_REVISION_GROUP, json!({"value": 1}))
                .unwrap(),
        )
        .unwrap();
    assert!(PolicyRevision::from_opened(&f.open(&unrelated, POLICY_REVISION_GROUP)).is_err());
}

#[test]
fn revision_binding_and_data_lineage_survive_a_policy_update() {
    let f = Fixture::new();
    let root = f.revision(f.draft(POLICY, "research"));
    let update = f.revision(
        f.draft(&POLICY.replace("version: 1", "version: 2"), "research")
            .parent(root.id(), PolicyRelation::Revise)
            .unwrap(),
    );
    let mut dag = PolicyDag::new();
    dag.admit(root.clone(), |_, _| Ok(true)).unwrap();
    let first = dag.select(root.id(), "research", |_| Ok(true)).unwrap();
    let source = f
        .writer()
        .seal(
            GovernedDraft::new("research.sample", first)
                .unwrap()
                .group("observations", json!({"count": 30}))
                .unwrap(),
        )
        .unwrap();
    let original = source.wire().to_owned();
    let opened = f.open(&source, "observations");
    assert_eq!(
        dag.resolve(opened.governance(), "research").unwrap().id(),
        root.id()
    );
    dag.admit(update.clone(), |_, _| Ok(true)).unwrap();
    let selected = dag.select(update.id(), "research", |_| Ok(true)).unwrap();
    let result = f
        .writer()
        .seal(
            opened
                .derive_under("research.aggregate", selected)
                .unwrap()
                .group("observations", json!({"total": 30}))
                .unwrap(),
        )
        .unwrap();
    let result = f.open(&result, "observations");
    assert_eq!(result.governance().revision_id(), Some(update.id()));
    assert_eq!(
        dag.resolve(result.governance(), "research").unwrap().id(),
        update.id()
    );
    let parent = &result.governance().get("source_lineage").unwrap()[0];
    assert_eq!(parent["policy_revision"], root.id());
    assert_eq!(parent["object_id"], source.id());
    assert_eq!(source.wire(), original);
    assert_eq!(
        f.open(&source, "observations").groups()["observations"]["count"],
        30
    );
    let aad: Value = serde_json::from_str(source.envelope()["tn_aad"].as_str().unwrap()).unwrap();
    assert_eq!(aad["tn.agents"].as_object().unwrap().len(), 2);
}

#[test]
fn a_valid_writer_signature_still_requires_matching_revision_content() {
    let f = Fixture::new();
    let root = f.revision(f.draft(POLICY, "research"));
    let mut dag = PolicyDag::new();
    dag.admit(root.clone(), |_, _| Ok(true)).unwrap();
    let selected = dag.select(root.id(), "research", |_| Ok(true)).unwrap();
    let object = f
        .writer()
        .seal(GovernedDraft::new("research.sample", selected).unwrap())
        .unwrap();
    for name in tn_core::agents_policy::REQUIRED_FIELDS {
        let changed = f.rewrite_governance(&object, |fields, _| {
            fields.insert(name.into(), json!("A changed obligation."));
        });
        let opened = f.reader().governance(&changed).unwrap();
        assert!(
            dag.resolve(opened.governance(), "research").is_err(),
            "{name}"
        );
    }
    let changed = f.rewrite_governance(&object, |_, marker| {
        marker["governed_by"] = json!(DeviceKey::generate().did());
    });
    assert!(dag
        .resolve(
            f.reader().governance(&changed).unwrap().governance(),
            "research"
        )
        .is_err());
    let other =
        Governance::from_markdown(f.device.did(), POLICY, "other.md", "research.sample").unwrap();
    let changed = f.rewrite_governance(&object, |fields, marker| {
        fields.insert("policy".into(), json!(other.policy_ref()));
        marker["policy"] = json!(other.policy_ref());
    });
    assert!(dag
        .resolve(
            f.reader().governance(&changed).unwrap().governance(),
            "research"
        )
        .is_err());
}

#[test]
fn revision_pointer_requires_valid_shape_and_an_accepted_exact_identity() {
    let f = Fixture::new();
    let root = f.revision(f.draft(POLICY, "research"));
    let mut dag = PolicyDag::new();
    dag.admit(root.clone(), |_, _| Ok(true)).unwrap();
    let object = f
        .writer()
        .seal(
            GovernedDraft::new(
                "research.sample",
                dag.select(root.id(), "research", |_| Ok(true)).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    for value in [
        Value::Null,
        json!(23),
        json!("latest"),
        json!(format!("sha256:{}", "A".repeat(64))),
    ] {
        let changed = f.rewrite_governance(&object, |fields, _| {
            fields.insert("policy_revision".into(), value);
        });
        assert!(f.reader().governance(&changed).is_err());
    }
    let unknown = format!("sha256:{}", "0".repeat(64));
    let changed = f.rewrite_governance(&object, |fields, _| {
        fields.insert("policy_revision".into(), json!(unknown));
    });
    assert!(dag
        .resolve(
            f.reader().governance(&changed).unwrap().governance(),
            "research"
        )
        .is_err());
    assert!(dag.select(&unknown, "research", |_| Ok(true)).is_err());
    let changed = f.rewrite_governance(&object, |fields, _| {
        fields.remove("policy_revision");
    });
    assert!(dag
        .resolve(
            f.reader().governance(&changed).unwrap().governance(),
            "research"
        )
        .is_err());
}

#[test]
fn decoding_a_revision_requires_its_assigned_group_access() {
    let f = Fixture::new();
    let root = f.revision(f.draft(POLICY, "research"));
    let reader = GovernedReader::new()
        .with_group("tn.agents", f.rules.clone())
        .unwrap();
    let admitted = reader
        .governance(root.object())
        .unwrap()
        .authorize("inspect", |_, _| Ok(true))
        .unwrap();
    let governance_only = reader.open(&admitted, std::iter::empty::<&str>()).unwrap();
    assert!(PolicyRevision::from_opened(&governance_only).is_err());
    assert!(reader.open(&admitted, [POLICY_REVISION_GROUP]).is_err());
    let reader = reader
        .with_group(POLICY_REVISION_GROUP, f.data.clone())
        .unwrap();
    assert_eq!(
        PolicyRevision::from_opened(&reader.open(&admitted, [POLICY_REVISION_GROUP]).unwrap())
            .unwrap()
            .id(),
        root.id()
    );
}

#[test]
fn equal_policy_content_can_have_distinct_authenticated_histories() {
    let f = Fixture::new();
    let first = f.revision(f.draft(POLICY, "research"));
    let second = f.revision(
        f.draft(POLICY, "research")
            .parent(first.id(), PolicyRelation::Revise)
            .unwrap(),
    );
    assert_eq!(
        first.governance().policy_ref(),
        second.governance().policy_ref()
    );
    assert_ne!(first.id(), second.id());
    let mut dag = PolicyDag::new();
    dag.admit(first.clone(), |_, _| Ok(true)).unwrap();
    dag.admit(second.clone(), |_, _| Ok(true)).unwrap();
    for revision in [&first, &second] {
        let selected = dag.select(revision.id(), "research", |_| Ok(true)).unwrap();
        assert_eq!(
            dag.resolve(&selected, "research").unwrap().id(),
            revision.id()
        );
    }
}
