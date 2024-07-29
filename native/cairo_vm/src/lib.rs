use juvix_cairo_vm::{anoma_cairo_vm_runner, program_input::ProgramInput};
use std::collections::HashMap;
use rustler::{NifResult, Error};

#[rustler::nif(schedule = "DirtyCpu")]
fn cairo_vm_runner(program_content: String, inputs: String) -> NifResult<(String, Vec<u8>, Vec<u8>, Vec<u8>)> {
    // Load program input
    let program_input = if inputs.is_empty() {
        ProgramInput::new(HashMap::new())
    } else {
        ProgramInput::from_json(&inputs).unwrap()
    };

    match anoma_cairo_vm_runner(&program_content.as_bytes(), program_input) {
        Ok(result) => Ok(result),
        Err(e) => {
            Err(Error::Term(Box::new(e.to_string())))
        }
    }
}

rustler::init!("Elixir.Cairo.CairoVM", [cairo_vm_runner]);
