use crate::error::CairoError;
use cairo_platinum_prover::{
    air::{verify_cairo_proof, PublicInputs, SegmentName},
    Felt252,
};
use rustler::NifResult;
use stark_platinum_prover::proof::options::{ProofOptions, SecurityLevel};
use starknet_crypto::poseidon_hash_many;
use starknet_types_core::felt::Felt;

#[rustler::nif(schedule = "DirtyCpu")]
fn cairo_verify(proof: Vec<u8>, public_input: Vec<u8>) -> NifResult<bool> {
    let proof_options = ProofOptions::new_secure(SecurityLevel::Conjecturable100Bits, 3);

    // Decode proof
    let proof = bincode::serde::decode_from_slice(&proof, bincode::config::standard())
        .map_err(CairoError::from)?
        .0;

    // Decode public inputs
    let pub_inputs = bincode::serde::decode_from_slice(&public_input, bincode::config::standard())
        .map_err(CairoError::from)?
        .0;

    Ok(verify_cairo_proof(&proof, &pub_inputs, &proof_options))
}

#[rustler::nif()]
fn cairo_get_output(public_input: Vec<u8>) -> NifResult<Vec<Vec<u8>>> {
    // Decode public inputs
    let (pub_inputs, _): (PublicInputs, usize) =
        bincode::serde::decode_from_slice(&public_input, bincode::config::standard())
            .map_err(CairoError::from)?;

    // Get output segments
    let output_segments = pub_inputs
        .memory_segments
        .get(&SegmentName::Output)
        .ok_or_else(|| CairoError::SegmentNotFound)?;

    let begin_addr: u64 = output_segments.begin_addr as u64;
    let stop_addr: u64 = output_segments.stop_ptr as u64;

    let mut output_values = Vec::new();
    for addr in begin_addr..stop_addr {
        // Convert addr to FieldElement (assuming this is the correct way to create a FieldElement from an address)
        let addr_field_element = Felt252::from(addr);

        if let Some(value) = pub_inputs.public_memory.get(&addr_field_element) {
            output_values.push(value.clone().to_bytes_be().to_vec());
        } else {
            return Err(CairoError::AddressNotFound(addr).into());
        }
    }

    Ok(output_values)
}

// Get the program from public inputs and return the program hash as the
// resource label
#[rustler::nif]
fn program_hash(public_inputs: Vec<u8>) -> NifResult<Vec<u8>> {
    let (pub_inputs, _): (PublicInputs, usize) =
        bincode::serde::decode_from_slice(&public_inputs, bincode::config::standard())
            .map_err(CairoError::from)?;
    let program_segments = pub_inputs
        .memory_segments
        .get(&SegmentName::Program)
        .ok_or_else(|| CairoError::SegmentNotFound)?;

    let begin_addr: u64 = program_segments.begin_addr as u64;
    let stop_addr: u64 = program_segments.stop_ptr as u64;

    let mut program = Vec::new();
    for addr in begin_addr..stop_addr {
        // Convert addr to FieldElement (assuming this is the correct way to create a FieldElement from an address)
        let addr_field_element = Felt252::from(addr);
        let value = pub_inputs
            .public_memory
            .get(&addr_field_element)
            .ok_or_else(|| CairoError::AddressNotFound(addr))?;
        program.push(Felt::from_raw(value.to_raw().limbs));
    }

    let program_hash = poseidon_hash_many(&program);

    Ok(program_hash.to_bytes_be().to_vec())
}
