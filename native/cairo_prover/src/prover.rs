use crate::error::CairoError;
use cairo_platinum_prover::{
    air::{generate_cairo_proof, PublicInputs, Segment, SegmentName},
    cairo_mem::CairoMemory,
    execution_trace::build_main_trace,
    register_states::RegisterStates,
    Felt252,
};
use hashbrown::HashMap;
use lambdaworks_math::traits::ByteConversion;
use rustler::NifResult;
use stark_platinum_prover::proof::options::{ProofOptions, SecurityLevel};

#[rustler::nif(schedule = "DirtyCpu")]
fn cairo_prove(
    trace: Vec<u8>,
    memory: Vec<u8>,
    public_input: Vec<u8>,
) -> NifResult<(Vec<u8>, Vec<u8>)> {
    if trace.is_empty() || memory.is_empty() || public_input.is_empty() {
        return Err(CairoError::EmptyInputs.into());
    }
    // Generating the prover args
    let register_states =
        RegisterStates::from_bytes_le(&trace).map_err(|_| CairoError::CairoImportError)?;

    let memory = CairoMemory::from_bytes_le(&memory).map_err(|_| CairoError::CairoImportError)?;

    // Handle public inputs
    let (rc_min, rc_max, public_memory, memory_segments) = parse_public_input(&public_input)
        .map_err(|e| CairoError::ParsePublicInputError(e.to_string()))?;

    let num_steps = register_states.steps();
    let mut pub_inputs = PublicInputs {
        pc_init: Felt252::from(register_states.rows[0].pc),
        ap_init: Felt252::from(register_states.rows[0].ap),
        fp_init: Felt252::from(register_states.rows[0].fp),
        pc_final: Felt252::from(register_states.rows[num_steps - 1].pc),
        ap_final: Felt252::from(register_states.rows[num_steps - 1].ap),
        range_check_min: Some(rc_min),
        range_check_max: Some(rc_max),
        memory_segments,
        public_memory,
        num_steps,
    };

    // Build main trace
    let main_trace = build_main_trace(&register_states, &memory, &mut pub_inputs);

    // Generating proof
    let proof_options = ProofOptions::new_secure(SecurityLevel::Conjecturable100Bits, 3);
    let proof = generate_cairo_proof(&main_trace, &pub_inputs, &proof_options)
        .map_err(|_| CairoError::ProvingError)?;

    // Encode proof and pub_inputs
    let proof_bytes = bincode::serde::encode_to_vec(proof, bincode::config::standard())
        .map_err(CairoError::from)?;
    let pub_input_bytes = bincode::serde::encode_to_vec(&pub_inputs, bincode::config::standard())
        .map_err(CairoError::from)?;

    Ok((proof_bytes, pub_input_bytes))
}

#[allow(clippy::type_complexity)]
fn parse_public_input(
    public_input: &[u8],
) -> Result<
    (
        u16,
        u16,
        HashMap<Felt252, Felt252>,
        HashMap<SegmentName, Segment>,
    ),
    &'static str,
> {
    let rc_min = u16::from_le_bytes(
        public_input
            .get(0..2)
            .ok_or("Input must be at least 2 bytes long for rc_min")?
            .try_into()
            .map_err(|_| "Failed to convert rc_min bytes")?,
    );

    let rc_max = u16::from_le_bytes(
        public_input
            .get(2..4)
            .ok_or("Input must be at least 4 bytes long for rc_max")?
            .try_into()
            .map_err(|_| "Failed to convert rc_max bytes")?,
    );

    let mem_len = u64::from_le_bytes(
        public_input
            .get(4..12)
            .ok_or("Input must be at least 12 bytes long for mem_len")?
            .try_into()
            .map_err(|_| "Failed to convert mem_len bytes")?,
    ) as usize;

    let mut public_memory: HashMap<Felt252, Felt252> = HashMap::new();
    for i in 0..mem_len {
        let start_index = 12 + i * 40;
        let addr = Felt252::from(u64::from_le_bytes(
            public_input
                .get(start_index..start_index + 8)
                .ok_or("Input too short for public memory address")?
                .try_into()
                .map_err(|_| "Failed to convert public memory address bytes")?,
        ));
        let value = Felt252::from_bytes_le(
            public_input
                .get(start_index + 8..start_index + 40)
                .ok_or("Input too short for public memory value")?,
        )
        .map_err(|_| "Failed to create Felt252 from bytes")?;
        public_memory.insert(addr, value);
    }

    let memory_segments_len = *public_input
        .get(12 + 40 * mem_len)
        .ok_or("Input too short for memory segments length")?
        as usize;
    let mut memory_segments = HashMap::new();
    for i in 0..memory_segments_len {
        let start_index = 12 + 40 * mem_len + 1 + i * 17;
        let segment_type = match public_input
            .get(start_index)
            .ok_or("Input too short for segment type")?
        {
            0u8 => SegmentName::RangeCheck,
            1u8 => SegmentName::Output,
            2u8 => SegmentName::Program,
            3u8 => SegmentName::Execution,
            4u8 => SegmentName::Ecdsa,
            5u8 => SegmentName::Pedersen,
            _ => continue, // skip unknown type
        };

        let segment_begin = u64::from_le_bytes(
            public_input
                .get(start_index + 1..start_index + 9)
                .ok_or("Input too short for segment begin")?
                .try_into()
                .map_err(|_| "Failed to convert segment begin bytes")?,
        );
        let segment_stop = u64::from_le_bytes(
            public_input
                .get(start_index + 9..start_index + 17)
                .ok_or("Input too short for segment stop")?
                .try_into()
                .map_err(|_| "Failed to convert segment stop bytes")?,
        );
        memory_segments.insert(segment_type, Segment::new(segment_begin, segment_stop));
    }

    Ok((rc_min, rc_max, public_memory, memory_segments))
}
