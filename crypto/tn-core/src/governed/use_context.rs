//! Complete, immutable application use admitted at a governed boundary.

use serde::{Deserialize, Deserializer, Serialize};

use super::invalid;
use crate::Result;

/// One requested application, purpose and operation tuple.
///
/// Applications must bind the requested application to their authenticated
/// caller or configured service before deciding admission.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct UseContext {
    application: String,
    purpose: String,
    operation: String,
}

impl UseContext {
    /// Require every use component; preserve its exact spelling for comparison.
    pub fn new(
        application: impl Into<String>,
        purpose: impl Into<String>,
        operation: impl Into<String>,
    ) -> Result<Self> {
        let context = Self {
            application: application.into(),
            purpose: purpose.into(),
            operation: operation.into(),
        };
        for (name, value) in [
            ("application", &context.application),
            ("purpose", &context.purpose),
            ("operation", &context.operation),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(invalid(format!(
                    "use {name} must be nonblank and exclude control characters"
                )));
            }
        }
        Ok(context)
    }

    /// Requested application identity, subject to the receiving authority check.
    pub fn application(&self) -> &str {
        &self.application
    }

    /// Purpose of this use.
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// Operation requested at this boundary.
    pub fn operation(&self) -> &str {
        &self.operation
    }
}

impl<'de> Deserialize<'de> for UseContext {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            application: String,
            purpose: String,
            operation: String,
        }
        let fields = Fields::deserialize(deserializer)?;
        Self::new(fields.application, fields.purpose, fields.operation)
            .map_err(serde::de::Error::custom)
    }
}
