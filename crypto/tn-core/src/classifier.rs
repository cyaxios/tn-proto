//! Field → group classifier.
//!
//! Stub: returns the configured `fields[<name>].group` if set, otherwise
//! `"default"` (or the first group alphabetically if no `default` group exists).
//! Production LLM classification stays Python-side — see RFC §6 Q3.

use crate::config::Config;

/// Resolve a field name to a group name given the config.
pub fn classify<'a>(cfg: &'a Config, field_name: &str) -> &'a str {
    if let Some(route) = cfg.fields.get(field_name) {
        return route.group.as_str();
    }
    if cfg.groups.contains_key("default") {
        "default"
    } else {
        cfg.groups.keys().next().map_or("default", String::as_str)
    }
}
