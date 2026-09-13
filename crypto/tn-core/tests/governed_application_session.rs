use serde_json::json;
use tn_core::governed::UseContext;
use tn_core::runtime::Session;

const POLICY: &str = "## hello.message\n### instruction\nRead the message.\n### use_for\nGreeting.\n### do_not_use_for\nOther uses.\n### consequences\nReview.\n### on_violation_or_error\nRefuse.\n";

#[test]
fn same_purpose_routes_by_object_type_and_releases_after_attachment() {
    let policy = format!(
        "{}\n{}",
        POLICY,
        POLICY.replace("hello.message", "hello.positions")
    );
    let session = Session::new(
        tn_core::runtime::Objects::ephemeral(
            &policy,
            "agents.md",
            &["prices", "holdings", "result"],
        )
        .unwrap(),
    );
    let use_context = UseContext::new("analytics", "valuation", "calculate").unwrap();
    session
        .configure_receive_for(
            Some("hello.message"),
            use_context.clone(),
            ["prices"],
            |ctx| Ok(ctx.object().object_type() == "hello.message"),
        )
        .unwrap();
    session
        .configure_receive_for(Some("hello.positions"), use_context, ["holdings"], |ctx| {
            Ok(ctx.object().object_type() == "hello.positions")
        })
        .unwrap();
    let prices = session
        .objects()
        .create_obj(
            "hello.message",
            session.policy("hello.message").unwrap(),
            "prices",
            json!({"price":125}),
        )
        .unwrap();
    let positions = session
        .objects()
        .create_obj(
            "hello.positions",
            session.policy("hello.positions").unwrap(),
            "holdings",
            json!({"quantity":2}),
        )
        .unwrap();
    let mut data = session.receive(&prices, "valuation").unwrap();
    let holdings = session.receive(&positions, "valuation").unwrap();
    data.include(&holdings).unwrap();
    assert_eq!(data.policies().unwrap().len(), 2);
    assert!(session
        .attach(&mut data, session.policy("hello.message").unwrap())
        .is_err());
    session
        .configure_attach(|ctx| Ok(ctx.data().policies()?.len() == 2))
        .unwrap();
    session
        .attach(&mut data, session.policy("hello.message").unwrap())
        .unwrap();
    data.set_group("result", json!({"total":250})).unwrap();
    data.retain_groups(["result"]).unwrap();
    session
        .configure_release(
            UseContext::new("analytics", "report", "publish").unwrap(),
            "review",
            "valuation.result",
            |ctx| {
                Ok(ctx.data().group("result").unwrap()["total"] == 250
                    && ctx.data().policies()?.len() == 2)
            },
        )
        .unwrap();
    assert!(session
        .release_checked(&mut data, "report", |_| Ok(false))
        .is_err());
    let output = session.release(&mut data, "report").unwrap();
    assert_eq!(output.object_type(), "valuation.result");
    assert!(!data.has_unreleased_changes());
    data.set_field("result", "total", json!(251)).unwrap();
    assert!(session.release(&mut data, "report").is_err());
    assert!(data.has_unreleased_changes());
    assert_eq!(data.snapshot().unwrap().id(), output.id());
}

#[test]
fn hello_world_and_exact_publication() {
    let session = Session::ephemeral(POLICY).unwrap();
    let expected = session.policy("hello.message").unwrap();
    let author = session.did().to_owned();
    session
        .configure_receive(
            UseContext::new("hello", "greeting", "read").unwrap(),
            ["default"],
            move |ctx| {
                assert_eq!(ctx.use_context().unwrap().application(), "hello");
                assert_eq!(ctx.use_context().unwrap().purpose(), "greeting");
                Ok(ctx.object().writer() == author && ctx.governance().matches_contract(&expected))
            },
        )
        .unwrap();
    let mut source = session
        .create_obj(
            json!({"message": "Hello, world!"}),
            session.policy("hello.message").unwrap(),
        )
        .unwrap();
    let received = session.receive(&source, "greeting").unwrap();
    assert_eq!(
        received.group("default").unwrap()["message"],
        "Hello, world!"
    );
    assert_eq!(source.object_type(), "hello.message");
    assert!(!source.snapshot().unwrap().wire().contains("Hello, world!"));
    session
        .receive(source.snapshot().unwrap(), "greeting")
        .unwrap();
    source
        .set_field("default", "message", json!("Changed"))
        .unwrap();
    assert!(session
        .receive(&source, "greeting")
        .err()
        .unwrap()
        .to_string()
        .contains("release"));
}

#[test]
fn missing_denied_duplicate_and_independent_sessions() {
    let session = Session::ephemeral(POLICY).unwrap();
    let source = session
        .create_obj(
            json!({"message":"hello"}),
            session.policy("hello.message").unwrap(),
        )
        .unwrap();
    assert!(session.receive(&source, "unknown").is_err());
    let usage = UseContext::new("hello", "greeting", "read").unwrap();
    session
        .configure_receive(usage.clone(), ["default"], |_| Ok(false))
        .unwrap();
    assert!(session.receive(&source, "greeting").is_err());
    assert!(session
        .configure_receive(usage.clone(), ["default"], |_| Ok(true))
        .is_err());
    let other = Session::ephemeral(POLICY).unwrap();
    assert_ne!(session.did(), other.did());
    other
        .configure_receive(usage, ["default"], |_| {
            panic!("no governance keys: must not reach admission")
        })
        .unwrap();
    assert!(other.receive(&source, "greeting").is_err());
}

#[test]
fn workflow_captures_routes_but_evaluates_live_authority() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let session = Session::ephemeral(POLICY).unwrap();
    assert!(session.workflow("read", "send").is_err());
    let active = Arc::new(AtomicBool::new(true));
    let authority = active.clone();
    session
        .configure_receive(
            UseContext::new("hello", "read", "read").unwrap(),
            ["default"],
            move |_| Ok(authority.load(Ordering::SeqCst)),
        )
        .unwrap();
    assert!(session.workflow("read", "send").is_err());
    session
        .configure_release(
            UseContext::new("hello", "send", "publish").unwrap(),
            "receiver",
            "hello.message",
            |_| Ok(true),
        )
        .unwrap();
    let work = session.workflow("read", "send").unwrap();
    // A new exact-type route must not replace the bound wildcard route.
    session
        .configure_receive_for(
            Some("hello.message"),
            UseContext::new("hello", "read", "read").unwrap(),
            ["default"],
            |_| Ok(false),
        )
        .unwrap();
    let source = session
        .create_obj(
            json!({"message":"hello"}),
            session.policy("hello.message").unwrap(),
        )
        .unwrap();
    assert!(session.receive(&source, "read").is_err());
    let mut data = work.receive(&source).unwrap();
    data.set_group("default", json!({"message":"updated"}))
        .unwrap();
    assert!(work.receive(&data).is_err());
    assert!(work.release_checked(&mut data, |_| Ok(false)).is_err());
    assert!(data.has_unreleased_changes());
    let published = work.release(&mut data).unwrap();
    assert_eq!(
        work.receive(&published).unwrap().group("default").unwrap()["message"],
        "updated"
    );
    active.store(false, Ordering::SeqCst);
    assert!(work.receive(&published).is_err());
    // Attachment configuration is captured too.
    session.configure_attach(|_| Ok(true)).unwrap();
    assert!(work
        .attach(&mut data, session.policy("hello.message").unwrap())
        .is_err());
    session
        .workflow("read", "send")
        .unwrap()
        .attach(&mut data, session.policy("hello.message").unwrap())
        .unwrap();
}

#[test]
fn agreed_verbs_keep_contracts_and_exact_publications() {
    use std::collections::BTreeMap;
    use tn_core::governed::GovernedObject;
    let session = Session::ephemeral(POLICY).unwrap();
    let mut data = session
        .create(
            json!({"message":"hello", "extra":1}),
            session.policy("hello.message").unwrap(),
        )
        .unwrap();
    let policies = data.policies().unwrap();
    assert_eq!(data.get("default", Some("message")).unwrap(), "hello");
    data.set("default", Some("message"), json!("changed"))
        .unwrap();
    let before = data.inspect();
    assert!(data
        .select(
            ["default"],
            Some(&BTreeMap::from([(
                "default".into(),
                vec!["missing".into()]
            )]))
        )
        .is_err());
    assert_eq!(data.revision(), before.revision());
    data.select(
        ["default"],
        Some(&BTreeMap::from([(
            "default".into(),
            vec!["message".into()],
        )])),
    )
    .unwrap();
    assert_eq!(
        data.get("default", None).unwrap(),
        json!({"message":"changed"})
    );
    assert_eq!(data.policies().unwrap(), policies);
    assert!(data.set("tn.agents", None, json!({})).is_err());
    assert!(data.forward().is_err());
    session
        .configure_release(
            UseContext::new("hello", "send", "publish").unwrap(),
            "receiver",
            "hello.message",
            |_| Ok(true),
        )
        .unwrap();
    let object = session.release(&mut data, "send").unwrap();
    let mut bytes = Vec::new();
    object.write(&mut bytes).unwrap();
    let restored = GovernedObject::read(bytes.as_slice()).unwrap();
    assert_eq!(restored.forward(), object.forward());
    assert_eq!(data.forward().unwrap(), object.forward());
    assert_eq!(restored.inspect(), object.inspect());
    assert_eq!(session.verify(restored.wire()).unwrap().forward(), object.forward());
}
