//! Compatibility read-policy adapter; all decision rules remain in tn-core.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use tn_core::runtime::{ReadContext, ReadRecordState, ReadTrustPolicy};

/// Evaluate already-scanned facts under the caller's frozen, resolved policy.
/// This function neither opens data nor turns supplied facts into admission.
#[pyfunction]
pub(crate) fn read_policy_evaluate<'py>(
    py: Python<'py>,
    policy: &Bound<'_, PyDict>,
    record: &Bound<'_, PyDict>,
    context: &Bound<'_, PyDict>,
) -> PyResult<Bound<'py, PyAny>> {
    crate::guard(|| {
        let policy: ReadTrustPolicy =
            serde_json::from_value(serde_json::Value::Object(crate::pydict_to_json(policy)?))
                .map_err(|e| PyValueError::new_err(format!("read policy: {e}")))?;
        let record: ReadRecordState =
            serde_json::from_value(serde_json::Value::Object(crate::pydict_to_json(record)?))
                .map_err(|e| PyValueError::new_err(format!("read record: {e}")))?;
        let context: ReadContext =
            serde_json::from_value(serde_json::Value::Object(crate::pydict_to_json(context)?))
                .map_err(|e| PyValueError::new_err(format!("read context: {e}")))?;
        let decision = policy.evaluate(&record, &context);
        crate::json_to_py(
            py,
            &serde_json::to_value(decision).map_err(|e| PyValueError::new_err(e.to_string()))?,
        )
    })
}
