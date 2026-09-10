//! Exact JSON-domain conversion for governed plaintext and immutable views.

use pyo3::exceptions::{PyOverflowError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};
use pyo3::IntoPyObjectExt;
use serde_json::{Map, Value};

pub(super) fn fields(dict: &Bound<'_, PyDict>) -> PyResult<Map<String, Value>> {
    match to_json(dict.as_any(), 0)? {
        Value::Object(fields) => Ok(fields),
        _ => unreachable!("input is a dictionary"),
    }
}

pub(super) fn to_json(value: &Bound<'_, PyAny>, depth: usize) -> PyResult<Value> {
    if depth > 64 {
        return Err(PyValueError::new_err(
            "governed JSON nesting exceeds 64 levels",
        ));
    }
    if value.is_none() {
        return Ok(Value::Null);
    }
    if value.is_instance_of::<PyBool>() {
        return Ok(Value::Bool(value.extract()?));
    }
    if value.is_instance_of::<PyInt>() {
        if let Ok(n) = value.extract::<i64>() {
            return Ok(Value::from(n));
        }
        return value
            .extract::<u64>()
            .map(Value::from)
            .map_err(|_| PyOverflowError::new_err("governed integers must fit i64 or u64"));
    }
    if value.is_instance_of::<PyFloat>() {
        return serde_json::Number::from_f64(value.extract()?)
            .map(Value::Number)
            .ok_or_else(|| PyValueError::new_err("governed floats must be finite"));
    }
    if value.is_instance_of::<PyString>() {
        return Ok(Value::String(value.extract()?));
    }
    if let Ok(dict) = value.downcast::<PyDict>() {
        let mut fields = Map::new();
        for (key, item) in dict.iter() {
            let key = key
                .extract::<String>()
                .map_err(|_| PyTypeError::new_err("governed JSON keys must be strings"))?;
            fields.insert(key, to_json(&item, depth + 1)?);
        }
        return Ok(Value::Object(fields));
    }
    if let Ok(list) = value.downcast::<PyList>() {
        return list
            .iter()
            .map(|v| to_json(&v, depth + 1))
            .collect::<PyResult<Vec<_>>>()
            .map(Value::Array);
    }
    if let Ok(tuple) = value.downcast::<PyTuple>() {
        return tuple
            .iter()
            .map(|v| to_json(&v, depth + 1))
            .collect::<PyResult<Vec<_>>>()
            .map(Value::Array);
    }
    Err(PyTypeError::new_err("governed fields require JSON values: null, bool, integer, finite float, string, array, or dict"))
}

pub(super) fn to_python<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    Ok(match value {
        Value::Null => py.None().into_bound(py),
        Value::Bool(v) => v.into_bound_py_any(py)?,
        Value::Number(v) => {
            if let Some(n) = v.as_i64() {
                n.into_bound_py_any(py)?
            } else if let Some(n) = v.as_u64() {
                n.into_bound_py_any(py)?
            } else {
                v.as_f64()
                    .ok_or_else(|| PyValueError::new_err("invalid JSON number"))?
                    .into_bound_py_any(py)?
            }
        }
        Value::String(v) => v.into_bound_py_any(py)?,
        Value::Array(values) => {
            let list = PyList::empty(py);
            for value in values {
                list.append(to_python(py, value)?)?;
            }
            list.into_any()
        }
        Value::Object(fields) => {
            let dict = PyDict::new(py);
            for (key, value) in fields {
                dict.set_item(key, to_python(py, value)?)?;
            }
            dict.into_any()
        }
    })
}

pub(super) fn wire(value: &Bound<'_, PyAny>) -> PyResult<String> {
    if let Ok(bytes) = value.downcast::<PyBytes>() {
        return String::from_utf8(bytes.as_bytes().to_vec())
            .map_err(|_| PyValueError::new_err("object wire must be UTF-8"));
    }
    value
        .extract::<String>()
        .map_err(|_| PyTypeError::new_err("object wire requires str or bytes"))
}
