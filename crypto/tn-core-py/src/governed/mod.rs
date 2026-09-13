//! PyO3 governed objects and independent, instance-owned sessions.

mod codec;
mod providers;
mod data;
mod dataset;
mod lineage;
mod objects;
mod reader;
mod revision;
mod session;
mod use_context;

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyOSError, PyValueError};
use pyo3::prelude::*;

create_exception!(governed, GovernedError, PyException);
create_exception!(governed, NotEntitled, GovernedError);
create_exception!(governed, NotAPublisher, GovernedError);
create_exception!(governed, UseDenied, GovernedError);
create_exception!(governed, VerificationError, GovernedError);
create_exception!(governed, SessionClosed, GovernedError);

fn to_py(error: tn_core::Error) -> PyErr {
    use tn_core::Error;
    match error {
        Error::NotEntitled { group } => NotEntitled::new_err(group),
        Error::NotAPublisher { group, reason } => {
            NotAPublisher::new_err(format!("{group}: {reason}"))
        }
        Error::UseDenied { operation } => UseDenied::new_err(operation),
        e @ Error::SealedObjectVerify { .. } => VerificationError::new_err(e.to_string()),
        Error::Io(e) => PyOSError::new_err(e.to_string()),
        e @ (Error::Malformed { .. }
        | Error::InvalidConfig(_)
        | Error::Yaml(_)
        | Error::ConfigEnvVarMissing { .. }
        | Error::ConfigEnvVarMalformed { .. }) => PyValueError::new_err(e.to_string()),
        other => GovernedError::new_err(other.to_string()),
    }
}

fn guard<T>(f: impl FnOnce() -> PyResult<T>) -> PyResult<T> {
    match tn_core::catch_panic(f) {
        Ok(result) => result,
        Err(message) => Err(GovernedError::new_err(format!("internal error: {message}"))),
    }
}

/// Register the governed interface in the combined Python wheel.
pub fn populate(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<session::PySession>()?;
    m.add_class::<session::PyRegisters>()?;
    m.add_class::<use_context::PyUseContext>()?;
    m.add_class::<objects::PyGovernance>()?;
    m.add_class::<objects::PyDraft>()?;
    m.add_class::<objects::PyObject>()?;
    m.add_class::<reader::PyReader>()?;
    m.add_class::<reader::PyGovernanceView>()?;
    m.add_class::<reader::PyAdmitted>()?;
    m.add_class::<reader::PyOpened>()?;
    m.add_class::<revision::PyPolicyRevisionDraft>()?;
    m.add_class::<revision::PyPolicyRevision>()?;
    m.add_class::<revision::PyPolicyParent>()?;
    m.add_class::<revision::PyPolicyRelation>()?;
    m.add_class::<revision::PyPolicyDag>()?;
    m.add_class::<dataset::PyContractBinding>()?;
    m.add_class::<dataset::PyEvaluatorArtifactSet>()?;
    m.add_class::<dataset::PyDatasetBinding>()?;
    m.add_class::<dataset::PyDatasetEditionDraft>()?;
    m.add_class::<dataset::PyDatasetEdition>()?;
    m.add_class::<dataset::PyDatasetCatalog>()?;
    m.add_class::<dataset::PyDatasetSelection>()?;
    m.add_class::<lineage::PyLineageVerifier>()?;
    m.add_class::<lineage::PyVerifiedLineage>()?;
    data::populate(m)?;
    providers::populate(m)?;
    for (name, exception) in [
        ("GovernedError", py.get_type::<GovernedError>()),
        ("NotEntitled", py.get_type::<NotEntitled>()),
        ("NotAPublisher", py.get_type::<NotAPublisher>()),
        ("UseDenied", py.get_type::<UseDenied>()),
        ("VerificationError", py.get_type::<VerificationError>()),
        ("SessionClosed", py.get_type::<SessionClosed>()),
    ] {
        exception.setattr("__module__", "tn.governed")?;
        m.add(name, exception)?;
    }
    Ok(())
}
