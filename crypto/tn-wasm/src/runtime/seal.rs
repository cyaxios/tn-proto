//! Portable seal/unseal bindings kept separate from the main runtime surface.

use wasm_bindgen::prelude::*;

use tn_core::{SealOptions, UnsealOptions, UnsealOutcome};

use super::WasmRuntime;
use crate::{js_to_json, json_to_js};

#[wasm_bindgen]
impl WasmRuntime {
    /// Seal a portable TN object with the configured group ciphers.
    ///
    /// `options` accepts `{ receipt?: boolean, aad?: object }`. The result is
    /// `{ envelope, wire }`; transport `wire` without reconstructing it.
    #[wasm_bindgen(js_name = "seal")]
    pub fn seal_js(
        &self,
        object_type: &str,
        fields: JsValue,
        options: Option<JsValue>,
    ) -> Result<JsValue, JsError> {
        let fields = object_value(fields, "seal: fields")?;
        let options = seal_options(options)?;
        let sealed = self
            .inner
            .seal(object_type, fields, &options)
            .map_err(core_error)?;
        json_to_js(&serde_json::json!({
            "envelope": sealed.envelope,
            "wire": sealed.wire,
        }))
    }

    /// Verify and open a portable TN object with configured reader material.
    /// `options` accepts `{ verify?: boolean, group?: string }`.
    #[wasm_bindgen(js_name = "unseal")]
    pub fn unseal_js(&self, source: &str, options: Option<JsValue>) -> Result<JsValue, JsError> {
        let options = unseal_options(options)?;
        let outcome = self.inner.unseal(source, &options).map_err(core_error)?;
        json_to_js(&unseal_outcome_json(outcome))
    }
}

fn seal_options(value: Option<JsValue>) -> Result<SealOptions, JsError> {
    let Some(value) = value else {
        return Ok(SealOptions::default());
    };
    let object = object_value(value, "seal: options")?;
    let mut options = SealOptions::default();
    if let Some(value) = object.get("receipt") {
        options.receipt = value
            .as_bool()
            .ok_or_else(|| JsError::new("seal: options.receipt must be a boolean"))?;
    }
    if let Some(value) = object.get("aad") {
        options.aad = value
            .as_object()
            .cloned()
            .ok_or_else(|| JsError::new("seal: options.aad must be an object"))?;
    }
    Ok(options)
}

fn unseal_options(value: Option<JsValue>) -> Result<UnsealOptions, JsError> {
    let Some(value) = value else {
        return Ok(UnsealOptions::default());
    };
    let object = object_value(value, "unseal: options")?;
    reject_filesystem_override(&object)?;
    let mut options = UnsealOptions::default();
    if let Some(value) = object.get("verify") {
        options.verify = value
            .as_bool()
            .ok_or_else(|| JsError::new("unseal: options.verify must be a boolean"))?;
    }
    if let Some(value) = object.get("group") {
        options.group = value
            .as_str()
            .ok_or_else(|| JsError::new("unseal: options.group must be a string"))?
            .to_owned();
    }
    Ok(options)
}

fn reject_filesystem_override(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), JsError> {
    if object.contains_key("asRecipient") || object.contains_key("as_recipient") {
        return Err(JsError::new(
            "unseal: asRecipient filesystem key bags are unavailable in WASM",
        ));
    }
    Ok(())
}

fn object_value(
    value: JsValue,
    label: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, JsError> {
    match js_to_json(value)? {
        serde_json::Value::Object(object) => Ok(object),
        _ => Err(JsError::new(&format!("{label} must be a JSON object"))),
    }
}

fn unseal_outcome_json(outcome: UnsealOutcome) -> serde_json::Value {
    let blocks: Vec<_> = outcome
        .sealed_blocks
        .into_iter()
        .map(sealed_block_json)
        .collect();
    serde_json::json!({
        "envelope": outcome.envelope,
        "plaintext": outcome.plaintext,
        "valid": {
            "signature": outcome.valid.signature,
            "row_hash": outcome.valid.row_hash,
        },
        "hidden_groups": outcome.hidden_groups,
        "sealed_blocks": blocks,
        "fields": outcome.fields,
    })
}

fn sealed_block_json(block: tn_core::SealedGroupInfo) -> serde_json::Value {
    serde_json::json!({
        "name": block.name,
        "ciphertext_b64": block.ciphertext_b64,
        "field_hashes": block.field_hashes,
        "aad_b64": block.aad_b64,
        "keystore_candidates": block.keystore_candidates,
    })
}

fn core_error(error: tn_core::Error) -> JsError {
    JsError::new(&error.to_string())
}
