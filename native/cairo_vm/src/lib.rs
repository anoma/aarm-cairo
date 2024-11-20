mod error;

use crate::error::CairoVMError;
use juvix_cairo_vm::{anoma_cairo_vm_runner, program_input::ProgramInput};
use rustler::NifResult;
use serde_json::Value;
use std::collections::HashMap;

#[allow(clippy::type_complexity)]
#[rustler::nif(schedule = "DirtyCpu")]
fn cairo_vm_runner(
    program_content: String,
    inputs: String,
) -> NifResult<(String, Vec<u8>, Vec<u8>, Vec<u8>)> {
    // Validate program content
    serde_json::from_str::<Value>(&program_content)
        .map_err(|_| CairoVMError::InvalidProgramContent)?;

    // Load program input
    let program_input = if inputs.is_empty() {
        ProgramInput::new(HashMap::new())
    } else {
        ProgramInput::from_json(&inputs).map_err(|_| CairoVMError::InvalidInputJSON)?
    };

    anoma_cairo_vm_runner(program_content.as_bytes(), program_input)
        .map_err(|e| CairoVMError::RuntimeError(e.to_string()).into())
}

rustler::init!("Elixir.Cairo.CairoVM", [cairo_vm_runner]);
