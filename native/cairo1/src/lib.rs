use juvix_cairo_vm::{anoma_cairo_vm_runner, program_input::ProgramInput};
use std::collections::HashMap;

#[rustler::nif(schedule = "DirtyCpu")]
fn cairo_vm_runner(program_content: String, inputs: String) -> (String, Vec<u8>, Vec<u8>) {
    // Load program input
    let program_input = if inputs.is_empty() {
        ProgramInput::new(HashMap::new())
    } else {
        ProgramInput::from_json(&inputs).unwrap()
    };

    // TODO: handle the error
    anoma_cairo_vm_runner(&program_content.as_bytes(), program_input).unwrap()
}

rustler::init!("Elixir.Cairo.Cairo1", [cairo_vm_runner]);
