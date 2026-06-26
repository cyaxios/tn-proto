//! `JsStorageAdapter` — bridges the Rust `tn_core::storage::Storage`
//! trait to a JS-supplied callbacks object.
//!
//! The JS host passes a single plain object whose properties are
//! function values (`Function` objects); we cache the references on
//! construction and invoke them by name from the Rust trait
//! implementation. Paths are sent across as strings; byte payloads as
//! `Uint8Array`; errors are caught and re-wrapped as `io::Error`.
//!
//! The expected JS shape:
//!
//! ```typescript
//! interface JsStorageCallbacks {
//!   read(path: string): Uint8Array;        // throws on missing
//!   write(path: string, data: Uint8Array): void;
//!   append(path: string, data: Uint8Array): void;
//!   exists(path: string): boolean;
//!   list(dir: string): string[];           // returns full paths
//!   rename(from: string, to: string): void;
//!   remove(path: string): void;
//!   createDirAll(dir: string): void;
//!   casWrite(path: string, prior: Uint8Array | null, newData: Uint8Array): void;
//!   // No `withAdvisoryLock` — wasm is single-process by definition;
//!   // the trait's default no-op implementation handles this.
//! }
//! ```
//!
//! All callbacks are **synchronous from Rust's POV**. The Node-side
//! `NodeStorageAdapter` (separate TS-side PR) implements these via
//! `fs.readFileSync` / `fs.writeFileSync` / etc. Browser-side
//! `IndexedDbStorageAdapter` (future) needs a sync shim — either
//! preload + cache at init time or `SharedArrayBuffer + Atomics.wait`.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use js_sys::{Array, Function, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;

use ::tn_core::storage::Storage;

/// Cached `js_sys::Function` references for each callback method on
/// the host-supplied storage object. `JsValue`-typed `Function`s are
/// `Send + Sync` in single-threaded wasm — the trait bound on
/// `Storage` is satisfied vacuously.
pub struct JsStorageAdapter {
    read_fn: Function,
    write_fn: Function,
    append_fn: Function,
    exists_fn: Function,
    list_fn: Function,
    rename_fn: Function,
    remove_fn: Function,
    create_dir_all_fn: Function,
    cas_write_fn: Function,
}

// SAFETY: wasm32 is single-threaded; `JsValue`/`Function` are not
// thread-shared. We only implement these bounds so `Arc<dyn Storage>`
// works as the `Runtime::init_with_storage` parameter type. Same
// pattern is used throughout `wasm-bindgen` consumers.
unsafe impl Send for JsStorageAdapter {}
unsafe impl Sync for JsStorageAdapter {}

impl JsStorageAdapter {
    /// Build an adapter from a JS object whose properties are the
    /// callback functions named above.
    ///
    /// Returns a Rust-side `Arc<dyn Storage>` so the caller can pass
    /// it straight to `Runtime::init_with_storage`.
    ///
    /// # Errors
    ///
    /// Returns `JsError` when the input isn't an object, or when one
    /// of the required callbacks is missing / not callable.
    pub fn from_js(js_obj: JsValue) -> Result<Arc<dyn Storage>, JsError> {
        if !js_obj.is_object() {
            return Err(JsError::new(
                "storage: expected a JS object with callback methods",
            ));
        }

        let get_fn = |name: &str| -> Result<Function, JsError> {
            let v = Reflect::get(&js_obj, &JsValue::from_str(name))
                .map_err(|e| JsError::new(&format!("storage: reading `{name}` threw: {e:?}")))?;
            v.dyn_into::<Function>().map_err(|_| {
                JsError::new(&format!(
                    "storage: property `{name}` is not a function (got {:?})",
                    js_obj
                ))
            })
        };

        let adapter = Self {
            read_fn: get_fn("read")?,
            write_fn: get_fn("write")?,
            append_fn: get_fn("append")?,
            exists_fn: get_fn("exists")?,
            list_fn: get_fn("list")?,
            rename_fn: get_fn("rename")?,
            remove_fn: get_fn("remove")?,
            create_dir_all_fn: get_fn("createDirAll")?,
            cas_write_fn: get_fn("casWrite")?,
        };
        Ok(Arc::new(adapter))
    }
}

/// Map a thrown JS value to an `io::Error`. `JSON.stringify` is
/// best-effort; many `Error` instances stringify to `"{}"` — we
/// fall back to the `Display` (toString) on those.
fn js_err_to_io(e: JsValue) -> io::Error {
    // Try `e.message` (Error objects) first.
    if let Ok(msg) = Reflect::get(&e, &JsValue::from_str("message")) {
        if let Some(s) = msg.as_string() {
            return io::Error::new(io::ErrorKind::Other, s);
        }
    }
    // Fall back to coercing the value itself to a string.
    let s = e
        .as_string()
        .or_else(|| js_sys::JSON::stringify(&e).ok().and_then(|j| j.as_string()))
        .unwrap_or_else(|| format!("{e:?}"));
    io::Error::new(io::ErrorKind::Other, s)
}

fn path_to_js(p: &Path) -> JsValue {
    JsValue::from_str(&p.to_string_lossy())
}

impl Storage for JsStorageAdapter {
    fn read_bytes(&self, path: &Path) -> io::Result<Vec<u8>> {
        let result = self
            .read_fn
            .call1(&JsValue::NULL, &path_to_js(path))
            .map_err(js_err_to_io)?;
        // The JS side returns a Uint8Array (or anything coercible to
        // one). `Uint8Array::new` on a non-Uint8Array value wraps it
        // in a fresh view backed by an empty ArrayBuffer, which would
        // give us silent corruption — so we type-check first.
        if !result.is_instance_of::<Uint8Array>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "storage.read: callback must return a Uint8Array",
            ));
        }
        let arr = Uint8Array::from(result);
        Ok(arr.to_vec())
    }

    fn write_bytes(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        // Allocate a Uint8Array view of `data` and pass it across.
        // `Uint8Array::from(&[u8])` copies into a fresh JS buffer; the
        // JS side owns the bytes after the call returns.
        let arr = Uint8Array::from(data);
        self.write_fn
            .call2(&JsValue::NULL, &path_to_js(path), &arr)
            .map_err(js_err_to_io)?;
        Ok(())
    }

    fn append_bytes(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        let arr = Uint8Array::from(data);
        self.append_fn
            .call2(&JsValue::NULL, &path_to_js(path), &arr)
            .map_err(js_err_to_io)?;
        Ok(())
    }

    fn exists(&self, path: &Path) -> bool {
        // Best-effort: any thrown error from the JS callback (e.g.
        // permission denied) collapses to `false`. The trait
        // signature returns `bool` not `io::Result<bool>` so a
        // higher-resolution answer isn't available; callers that
        // need to distinguish "absent" from "errored" use `read`
        // and check `io::Error::kind`.
        match self.exists_fn.call1(&JsValue::NULL, &path_to_js(path)) {
            Ok(v) => v.as_bool().unwrap_or(false),
            Err(_) => false,
        }
    }

    fn list(&self, dir: &Path) -> io::Result<Vec<PathBuf>> {
        let result = self
            .list_fn
            .call1(&JsValue::NULL, &path_to_js(dir))
            .map_err(js_err_to_io)?;
        let arr: Array = result.dyn_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "storage.list: callback must return an array of strings",
            )
        })?;
        let mut out = Vec::with_capacity(arr.length() as usize);
        for i in 0..arr.length() {
            let v = arr.get(i);
            let s = v.as_string().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "storage.list: array element is not a string",
                )
            })?;
            out.push(PathBuf::from(s));
        }
        Ok(out)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.rename_fn
            .call2(&JsValue::NULL, &path_to_js(from), &path_to_js(to))
            .map_err(js_err_to_io)?;
        Ok(())
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        self.remove_fn
            .call1(&JsValue::NULL, &path_to_js(path))
            .map_err(js_err_to_io)?;
        Ok(())
    }

    fn create_dir_all(&self, dir: &Path) -> io::Result<()> {
        self.create_dir_all_fn
            .call1(&JsValue::NULL, &path_to_js(dir))
            .map_err(js_err_to_io)?;
        Ok(())
    }

    fn cas_write(&self, path: &Path, prior: Option<&[u8]>, new: &[u8]) -> io::Result<()> {
        let prior_js = match prior {
            Some(b) => Uint8Array::from(b).into(),
            None => JsValue::NULL,
        };
        let new_js: JsValue = Uint8Array::from(new).into();
        // call3 is the right arity for path+prior+new.
        let path_js = path_to_js(path);
        match self
            .cas_write_fn
            .call3(&JsValue::NULL, &path_js, &prior_js, &new_js)
        {
            Ok(_) => Ok(()),
            Err(e) => {
                // Round-2 cleanup: preserve `AlreadyExists` semantics
                // across the JS boundary so the keystore CAS-retry loop
                // can match on `io::Error::kind()` rather than substring
                // -match on the message. The JS adapter signals CAS
                // mismatch by either (a) throwing an Error whose
                // `name === "ConditionalWriteFailedError"` or (b)
                // including the literal substring `"cas-mismatch"` in
                // the message. Anything else falls through to the
                // generic `Other` kind.
                let name_is_conflict = Reflect::get(&e, &JsValue::from_str("name"))
                    .ok()
                    .and_then(|n| n.as_string())
                    .is_some_and(|s| s == "ConditionalWriteFailedError");
                let io_err = js_err_to_io(e);
                let msg_is_conflict = io_err.to_string().contains("cas-mismatch");
                if name_is_conflict || msg_is_conflict {
                    Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        io_err.to_string(),
                    ))
                } else {
                    Err(io_err)
                }
            }
        }
    }

    // No `with_advisory_lock` override — the trait's default no-op
    // implementation runs `f()` directly, which is the correct
    // behaviour for single-process wasm.
}
