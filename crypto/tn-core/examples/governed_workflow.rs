//! Run a complete governed object workflow or verify a Python-produced wire file.
use serde_json::json;
use tn_core::governed::{GovernedObject, UseContext};
use tn_core::runtime::Objects;

const POLICY: &str = "## finance.account\n### instruction\nCalculate account totals.\n### use_for\nPortfolio analysis.\n### do_not_use_for\nIndividual disclosure.\n### consequences\nContract review.\n### on_violation_or_error\nRefuse release.\n";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "--verify" {
        let wire = std::fs::read_to_string(&args[2])?;
        let object = GovernedObject::parse(&wire)?;
        println!(
            "{}",
            json!({"id":object.id(), "wire":object.wire(), "writer":object.writer()})
        );
        return Ok(());
    }
    if args.len() != 1 {
        return Err("usage: governed_workflow [--verify wire-file]".into());
    }
    let session = Objects::ephemeral(POLICY, "portfolio.md", &["finance"])?;
    let policy = session.draft("finance.account")?.governance().clone();
    let mut account = session.create_obj(
        "finance.account",
        policy.clone(),
        "finance",
        json!({
            "rows": [{"quantity":2, "unit_price":1200}, {"quantity":3, "unit_price":500}]
        }),
    )?;
    let source = session.release_for(
        &mut account,
        "finance.account",
        &UseContext::new("data.service", "portfolio_analysis", "supply_account")?,
        "analytics",
        |_| Ok(true),
    )?;

    let input_use = UseContext::new("analytics", "portfolio_analysis", "calculate_total")?;
    let mut working =
        session.receive_for(source.wire(), &input_use, ["finance"], None, |context| {
            Ok(context.object().id() == source.id()
                && context.object().writer() == session.did()
                && context.policies()? == vec![policy.clone()])
        })?;
    let rows = working.get_path(&[json!("finance"), json!("rows")])?;
    let total: i64 = rows
        .as_array()
        .ok_or("rows must be an array")?
        .iter()
        .map(|row| {
            Ok(row["quantity"]
                .as_i64()
                .ok_or("quantity must be an integer")?
                * row["unit_price"]
                    .as_i64()
                    .ok_or("unit_price must be an integer")?)
        })
        .collect::<Result<Vec<_>, &str>>()?
        .into_iter()
        .sum();
    working.set_group("finance", json!({"total_minor_units":total}))?;
    let released = session.release_for(
        &mut working,
        "finance.total",
        &UseContext::new("analytics", "portfolio_analysis", "release_total")?,
        "reporting",
        |context| Ok(context.data().policies()? == vec![policy.clone()]),
    )?;
    println!(
        "{}",
        json!({
            "source_id":source.id(), "source_wire":source.wire(),
            "output_id":released.id(), "output_wire":released.wire(), "total_minor_units":total
        })
    );
    Ok(())
}
