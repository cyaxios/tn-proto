//! `JsHandler` — bridges the Rust `tn_core::handlers::TnHandler` trait
//! to a JS-supplied callbacks object.
//!
//! The shape mirrors `JsStorageAdapter`: a single JS object whose
//! properties are function values, cached on construction and invoked
//! by name from the Rust trait impl. Mirrors Python's `TNHandler`
//! subclass surface and TS's `NodeRuntime.addHandler` callback shape.
//!
//! Expected JS shape:
//!
//! ```typescript
//! interface JsHandlerCallbacks {
//!   name: string;
//!   emit(envelope: object, rawLine: Uint8Array): void;     // required
//!   accepts?(envelope: object): boolean;                   // default true
//!   close?(): void;                                        // default noop
//! }
//! ```
//!
//! All callbacks are **synchronous from Rust's POV** — matches the
//! `TnHandler` trait signatures. Errors thrown from `emit` are
//! swallowed (consistent with `Runtime::fan_out_to_handlers`); a
//! failing handler must never abort the emit pipeline.

use js_sys::{Function, Reflect, Uint8Array};
use serde_json::Value;
use wasm_bindgen::prelude::*;

use ::tn_core::handlers::TnHandler;

/// Cached `js_sys::Function` references for each callback method on
/// the host-supplied handler object.
pub struct JsHandler {
    name: String,
    accepts_fn: Option<Function>,
    emit_fn: Function,
    close_fn: Option<Function>,
}

// SAFETY: wasm32 is single-threaded; `JsValue`/`Function` are not
// thread-shared. Same pattern as `JsStorageAdapter` — these unsafe
// impls only exist so `Arc<dyn TnHandler>` (which requires
// `Send + Sync`) works across the JS boundary.
unsafe impl Send for JsHandler {}
unsafe impl Sync for JsHandler {}

impl JsHandler {
    /// Build a handler from a JS object. `name` and `emit` are
    /// required; `accepts` and `close` are optional.
    ///
    /// # Errors
    ///
    /// Returns `JsError` when the input isn't an object, when `name`
    /// is missing / not a string, when `emit` is missing / not a
    /// function, or when `accepts` / `close` are present but not
    /// functions.
    pub fn from_js(callbacks: JsValue) -> Result<Self, JsError> {
        if !callbacks.is_object() {
            return Err(JsError::new(
                "addHandler: expected a JS object with at least { name, emit }",
            ));
        }

        let name_val = Reflect::get(&callbacks, &JsValue::from_str("name"))
            .map_err(|e| JsError::new(&format!("addHandler: reading `name` threw: {e:?}")))?;
        let name = name_val
            .as_string()
            .ok_or_else(|| JsError::new("addHandler: `name` must be a string"))?;

        let emit_val = Reflect::get(&callbacks, &JsValue::from_str("emit"))
            .map_err(|e| JsError::new(&format!("addHandler: reading `emit` threw: {e:?}")))?;
        let emit_fn = emit_val
            .dyn_into::<Function>()
            .map_err(|_| JsError::new("addHandler: `emit` must be a function"))?;

        let accepts_fn = optional_fn(&callbacks, "accepts")?;
        let close_fn = optional_fn(&callbacks, "close")?;

        Ok(Self {
            name,
            accepts_fn,
            emit_fn,
            close_fn,
        })
    }
}

/// Extract an optional function property. Missing / undefined / null
/// returns `Ok(None)`; present-but-not-a-function returns an error.
fn optional_fn(obj: &JsValue, name: &str) -> Result<Option<Function>, JsError> {
    let v = Reflect::get(obj, &JsValue::from_str(name))
        .map_err(|e| JsError::new(&format!("addHandler: reading `{name}` threw: {e:?}")))?;
    if v.is_undefined() || v.is_null() {
        return Ok(None);
    }
    v.dyn_into::<Function>()
        .map(Some)
        .map_err(|_| JsError::new(&format!("addHandler: `{name}` must be a function")))
}

impl TnHandler for JsHandler {
    fn name(&self) -> &str {
        &self.name
    }

    fn accepts(&self, envelope: &Value) -> bool {
        match &self.accepts_fn {
            None => true,
            Some(f) => {
                let env_js = crate::json_to_js(envelope).unwrap_or(JsValue::NULL);
                f.call1(&JsValue::NULL, &env_js)
                    .ok()
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            }
        }
    }

    fn emit(&self, envelope: &Value, raw_line: &[u8]) {
        let env_js = crate::json_to_js(envelope).unwrap_or(JsValue::NULL);
        let line_arr = Uint8Array::from(raw_line);
        // Errors swallowed — handlers must not fail the emit pipeline.
        // Matches Rust's `fan_out_to_handlers` contract: a downstream
        // handler having a bad day never aborts the publisher.
        let _ = self.emit_fn.call2(&JsValue::NULL, &env_js, &line_arr);
    }

    fn close(&self) {
        if let Some(f) = &self.close_fn {
            let _ = f.call0(&JsValue::NULL);
        }
    }
}
