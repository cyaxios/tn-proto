//! Catch a Rust panic at a language-binding boundary and turn it into a typed,
//! catchable host-language error.
//!
//! The TN core backs a Python wheel (`tn-core-py`) and a wasm package. The
//! architectural law is that no TN path may surface an exception the caller did
//! not explicitly request: a panic crossing the FFI boundary becomes a pyo3
//! `PanicException` (which subclasses `BaseException`, so it slips past an
//! ordinary `except Exception:`) — or, on a wasm `panic = unwind` build, a
//! trap. [`catch_panic`] lets a binding run core code, catch any panic, and map
//! it to its own error type so the failure is contained and observable rather
//! than crashing user space.
//!
//! Note: this relies on unwinding. On a `panic = abort` target (the default for
//! `wasm32-unknown-unknown`) a panic aborts before [`catch_panic`] can run, so
//! the wasm bindings rely on removing reachable panics instead.

use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Run `f`, returning its value, or `Err(message)` if it panicked.
///
/// The error string is the panic payload's message when it was a `&str` or
/// `String` (the common cases for `panic!`, `unwrap`, `expect`, `unreachable!`),
/// and a generic marker otherwise.
pub fn catch_panic<F, T>(f: F) -> std::result::Result<T, String>
where
    F: FnOnce() -> T,
{
    // `AssertUnwindSafe`: the binding owns the closure and re-establishes a
    // clean state on the host side after an error, so unwind-safety of captured
    // state is the caller's contract, not something we can prove generically.
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => Ok(value),
        Err(payload) => Err(panic_message(payload.as_ref())),
    }
}

/// Best-effort extraction of a human-readable message from a panic payload.
fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "panic with non-string payload".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_value_when_no_panic() {
        assert_eq!(catch_panic(|| 2 + 2), Ok(4));
    }

    #[test]
    fn catches_static_str_panic() {
        let err = catch_panic(|| -> i32 { panic!("boom") }).unwrap_err();
        assert!(err.contains("boom"), "got: {err}");
    }

    #[test]
    fn catches_formatted_string_panic() {
        // `panic!("{}", ...)` yields a `String` payload, not a `&str`.
        let err = catch_panic(|| -> i32 {
            let who = "reducer";
            panic!("drift in {who}")
        })
        .unwrap_err();
        assert!(err.contains("drift in reducer"), "got: {err}");
    }

    #[test]
    fn catches_unwrap_panic() {
        let err = catch_panic(|| -> i32 { None::<i32>.unwrap() }).unwrap_err();
        assert!(!err.is_empty());
    }
}
