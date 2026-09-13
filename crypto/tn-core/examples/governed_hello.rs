//! Run: cargo run -p tn-core --example governed_hello
use serde_json::json;
use tn_core::governed::{DataObject, UseContext};
use tn_core::runtime::Session;
use tn_core::Result;

const POLICY: &str = "## hello.message\n### instruction\nRead the message.\n### use_for\nGreeting.\n### do_not_use_for\nOther uses.\n### consequences\nReview.\n### on_violation_or_error\nRefuse.\n";

fn configure(session: &Session<'_>) -> Result<()> {
    let writer = session.did().to_owned();
    let expected = session.policy("hello.message")?;
    session.configure_receive(
        UseContext::new("hello", "greeting", "read")?,
        ["default"],
        move |context| {
            let policies = context.policies()?;
            Ok(context.object().writer() == writer
                && policies.len() == 1
                && policies[0].matches_contract(&expected))
        },
    )
}

fn hello(session: &Session<'_>) -> Result<DataObject> {
    session.create(
        json!({"message": "Hello, world!"}),
        session.policy("hello.message")?,
    )
}

fn main() -> Result<()> {
    let session = Session::ephemeral(POLICY)?;
    configure(&session)?;
    let message = session.receive(&hello(&session)?, "greeting")?;
    println!(
        "{}",
        message.get("default", Some("message"))?.as_str().unwrap()
    );
    Ok(())
}
