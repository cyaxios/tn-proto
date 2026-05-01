//! PyO3 bindings for tn_core::admin_catalog + admin_reduce.
//!
//! Exposed as `tn_core_py._core.admin.{kinds, reduce, validate_emit}`.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use serde_json::Value;

use tn_core::admin_catalog::{self, FieldType};
use tn_core::admin_reduce;

#[pyfunction]
fn kinds(py: Python<'_>) -> PyResult<Bound<'_, PyList>> {
    let list = PyList::empty_bound(py);
    for k in admin_catalog::CATALOG {
        let d = PyDict::new_bound(py);
        d.set_item("event_type", k.event_type)?;
        d.set_item("sign", k.sign)?;
        d.set_item("sync", k.sync)?;
        let schema = PyList::empty_bound(py);
        for (name, ftype) in k.schema {
            let pair = PyList::empty_bound(py);
            pair.append(*name)?;
            pair.append(field_type_str(*ftype))?;
            schema.append(pair)?;
        }
        d.set_item("schema", schema)?;
        list.append(d)?;
    }
    Ok(list)
}

fn field_type_str(t: FieldType) -> &'static str {
    match t {
        FieldType::String => "string",
        FieldType::OptionalString => "optional_string",
        FieldType::Int => "int",
        FieldType::OptionalInt => "optional_int",
        FieldType::Iso8601 => "iso8601",
    }
}

#[pyfunction]
fn reduce(py: Python<'_>, envelope: &Bound<'_, PyDict>) -> PyResult<PyObject> {
    let json_map = crate::pydict_to_json(envelope)?;
    let value = Value::Object(json_map);
    let delta = admin_reduce::reduce(&value).map_err(|e| PyValueError::new_err(format!("{e}")))?;
    let delta_value = serde_json::to_value(&delta)
        .map_err(|e| PyValueError::new_err(format!("delta -> json: {e}")))?;
    let out = crate::json_to_py(py, &delta_value)?;
    Ok(out.into())
}

#[pyfunction]
fn validate_emit(event_type: &str, fields: &Bound<'_, PyDict>) -> PyResult<()> {
    let json_map = crate::pydict_to_json(fields)?;
    admin_catalog::validate_emit(event_type, &json_map)
        .map_err(|e| PyValueError::new_err(format!("{e}")))
}

pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new_bound(parent.py(), "admin")?;
    m.add_function(wrap_pyfunction!(kinds, &m)?)?;
    m.add_function(wrap_pyfunction!(reduce, &m)?)?;
    m.add_function(wrap_pyfunction!(validate_emit, &m)?)?;
    parent.add_submodule(&m)?;
    Ok(())
}
