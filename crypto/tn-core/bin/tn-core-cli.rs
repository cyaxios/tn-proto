//! tn-core-cli: thin CLI wrapper over tn_core::Runtime. Useful for manual
//! smoke-testing and cross-runtime (Python↔Rust) interop tests.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tn_core::Runtime;

#[derive(Parser)]
#[command(
    name = "tn-core-cli",
    about = "Minimal CLI over the tn-core Rust runtime (init/log/read)"
)]
struct Cli {
    /// Path to tn.yaml.
    #[arg(long, default_value = "tn.yaml")]
    yaml: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Initialize (validates config, loads keystore, prints DID + log path).
    Init,
    /// Emit one event. Fields are given as KEY=VALUE pairs; VALUE is parsed
    /// as JSON if it parses, else treated as a string.
    Log {
        #[arg(long, default_value = "info")]
        level: String,
        #[arg(long)]
        event_type: String,
        #[arg(trailing_var_arg = true)]
        fields: Vec<String>,
    },
    /// Read all entries from the log and print them as one JSON object per line:
    /// `{"envelope": {...}, "plaintext": {group_name: {...}}}`.
    Read,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let rt = Runtime::init(&cli.yaml)?;
    match cli.cmd {
        Cmd::Init => {
            println!("did={}", rt.did());
            println!("log={}", rt.log_path().display());
        }
        Cmd::Log {
            level,
            event_type,
            fields,
        } => {
            let mut map = serde_json::Map::new();
            for kv in fields {
                let (k, v) = kv
                    .split_once('=')
                    .ok_or_else(|| format!("fields must be KEY=VALUE, got {kv:?}"))?;
                // Parse as JSON if possible; fall back to raw string.
                let val: serde_json::Value = serde_json::from_str(v)
                    .unwrap_or_else(|_| serde_json::Value::String(v.to_string()));
                map.insert(k.to_string(), val);
            }
            rt.emit(&level, &event_type, map)?;
            println!("{}", serde_json::json!({"ok": true}));
        }
        Cmd::Read => {
            for entry in rt.read_raw()? {
                let mut pt_obj = serde_json::Map::new();
                for (k, v) in entry.plaintext_per_group {
                    pt_obj.insert(k, v);
                }
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({
                        "envelope": entry.envelope,
                        "plaintext": pt_obj,
                    }))?
                );
            }
        }
    }
    Ok(())
}
