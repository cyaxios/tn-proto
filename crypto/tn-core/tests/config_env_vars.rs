//! Env-var substitution in tn.yaml loading.
//!
//! Mirrors `python/tests/test_config_env_vars.py` and
//! `ts-sdk/test/config_env_vars.test.ts` for cross-language parity.
//!
//! NOTE: tests in this file mutate process-global env vars. They are
//! kept in a single `#[test]` group serialized via a `Mutex` to avoid
//! cross-thread interleaving when `cargo test` runs them in parallel.

use std::path::Path;
use std::sync::Mutex;

use tn_core::{config::substitute_env_vars, Error};

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn with_env<F>(vars: &[(&str, Option<&str>)], f: F)
where
    F: FnOnce(),
{
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let prev: Vec<(String, Option<String>)> = vars
        .iter()
        .map(|(k, _)| ((*k).to_string(), std::env::var(k).ok()))
        .collect();
    for (k, v) in vars {
        match v {
            Some(val) => std::env::set_var(k, val),
            None => std::env::remove_var(k),
        }
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    for (k, v) in prev {
        match v {
            Some(val) => std::env::set_var(k, val),
            None => std::env::remove_var(k),
        }
    }
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}

fn src() -> &'static Path {
    Path::new("/tmp/tn.yaml")
}

#[test]
fn required_var_present_is_substituted() {
    with_env(&[("TN_RS_TEST_HOST", Some("atlas.cluster.example"))], || {
        let out = substitute_env_vars("uri: ${TN_RS_TEST_HOST}\n", src()).unwrap();
        assert_eq!(out, "uri: atlas.cluster.example\n");
    });
}

#[test]
fn required_var_absent_errors_with_var_and_path() {
    with_env(&[("TN_RS_TEST_MISSING", None)], || {
        let err = substitute_env_vars("uri: ${TN_RS_TEST_MISSING}\n", src()).unwrap_err();
        match err {
            Error::ConfigEnvVarMissing { var, path, line } => {
                assert_eq!(var, "TN_RS_TEST_MISSING");
                assert_eq!(path, src());
                assert_eq!(line, 1);
            }
            other => panic!("expected ConfigEnvVarMissing, got {other:?}"),
        }
    });
}

#[test]
fn default_used_when_var_absent() {
    with_env(&[("TN_RS_TEST_ABSENT", None)], || {
        let out = substitute_env_vars("id: ${TN_RS_TEST_ABSENT:-fallback_id}\n", src()).unwrap();
        assert_eq!(out, "id: fallback_id\n");
    });
}

#[test]
fn default_ignored_when_var_present() {
    with_env(&[("TN_RS_TEST_PRESENT", Some("real_value"))], || {
        let out = substitute_env_vars("id: ${TN_RS_TEST_PRESENT:-fallback}\n", src()).unwrap();
        assert_eq!(out, "id: real_value\n");
    });
}

#[test]
fn empty_default_substitutes_empty_string() {
    with_env(&[("TN_RS_TEST_EMPTY", None)], || {
        let out = substitute_env_vars("id: \"${TN_RS_TEST_EMPTY:-}\"\n", src()).unwrap();
        assert_eq!(out, "id: \"\"\n");
    });
}

#[test]
fn escape_double_dollar_passes_through() {
    let out = substitute_env_vars("note: $${LITERAL}\n", src()).unwrap();
    assert_eq!(out, "note: ${LITERAL}\n");
}

#[test]
fn mixed_substitutions_yaml() {
    with_env(
        &[
            ("TN_RS_TEST_DID", Some("did:key:zABC")),
            ("TN_RS_TEST_LOG_DIR", None),
        ],
        || {
            let text = "ceremony:\n  id: ${TN_RS_TEST_DID}\n  literal: $${LITERAL_TEMPLATE}\nlogs:\n  path: ${TN_RS_TEST_LOG_DIR:-./.tn/logs/tn.ndjson}\n";
            let out = substitute_env_vars(text, src()).unwrap();
            assert!(out.contains("id: did:key:zABC"));
            assert!(out.contains("literal: ${LITERAL_TEMPLATE}"));
            assert!(out.contains("path: ./.tn/logs/tn.ndjson"));
        },
    );
}

#[test]
fn malformed_var_name_errors() {
    let err = substitute_env_vars("id: ${1FOO}\n", src()).unwrap_err();
    match err {
        Error::ConfigEnvVarMalformed { token, path, line } => {
            assert!(token.contains("${1FOO}"), "token was {token:?}");
            assert_eq!(path, src());
            assert_eq!(line, 1);
        }
        other => panic!("expected ConfigEnvVarMalformed, got {other:?}"),
    }
}

#[test]
fn unclosed_brace_errors() {
    let err = substitute_env_vars("id: ${UNCLOSED\n", src()).unwrap_err();
    match err {
        Error::ConfigEnvVarMalformed { .. } => {}
        other => panic!("expected ConfigEnvVarMalformed, got {other:?}"),
    }
}

#[test]
fn no_recursive_expansion() {
    with_env(
        &[
            ("TN_RS_TEST_RECURSE", Some("${TN_RS_TEST_NESTED}")),
            ("TN_RS_TEST_NESTED", Some("should_not_expand")),
        ],
        || {
            let out = substitute_env_vars("v: ${TN_RS_TEST_RECURSE}\n", src()).unwrap();
            assert_eq!(out, "v: ${TN_RS_TEST_NESTED}\n");
        },
    );
}

#[test]
fn lone_dollar_passes_through() {
    let out = substitute_env_vars("price: $5\n", src()).unwrap();
    assert_eq!(out, "price: $5\n");
}

#[test]
fn line_number_tracked_across_newlines() {
    with_env(&[("TN_RS_TEST_LINE3", None)], || {
        let err = substitute_env_vars("a: 1\nb: 2\nc: ${TN_RS_TEST_LINE3}\n", src()).unwrap_err();
        match err {
            Error::ConfigEnvVarMissing { line, .. } => assert_eq!(line, 3),
            other => panic!("expected missing, got {other:?}"),
        }
    });
}
