// Demonstrates local recipient invitation flow. One ephemeral ceremony mints a
// `tn-invite-*.zip`, and a second ceremony accepts it into its keystore.

use tn_proto::{MintInvitationOptions, ReadOptions, Tn};

fn main() -> tn_proto::Result<()> {
    let producer = Tn::ephemeral()?;
    let consumer = Tn::ephemeral()?;

    let out_path = producer
        .log_path()
        .parent()
        .expect("ephemeral log should have a parent")
        .join("tn-invite-example.zip");

    let minted = producer.inbox().mint_invite_path(
        consumer.did(),
        &out_path,
        MintInvitationOptions {
            from_email: Some("producer@example.test".to_string()),
            invitation_id: Some("example-invite".to_string()),
            note: Some("Welcome to the default group".to_string()),
            ..MintInvitationOptions::default()
        },
    )?;
    println!("wrote invite: {}", minted.path.display());
    println!("inner kit: {}", minted.kit_entry_name);

    let accepted = consumer.inbox().accept_path(&out_path)?;
    println!(
        "accepted group '{}' from {}",
        accepted.group_name(),
        accepted.from_email()
    );
    println!("installed kit: {}", accepted.kit_path.display());

    for entry in consumer.read(ReadOptions::default())? {
        if entry.event_type() == Some("tn.enrolment.absorbed") {
            println!("attestation: {entry:#?}");
        }
    }

    Ok(())
}
