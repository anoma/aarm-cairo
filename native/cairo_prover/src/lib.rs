use cairo_platinum_prover::{
    air::{generate_cairo_proof, verify_cairo_proof, PublicInputs, Segment, SegmentName},
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
fn cairo_prove(trace: Vec<u8>, memory: Vec<u8>, public_input: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    // Generating the prover args
    let register_states = RegisterStates::from_bytes_le(&trace).unwrap();
    let memory = CairoMemory::from_bytes_le(&memory).unwrap();

    // Handle public inputs
    let rc_min = u16::from_le_bytes(public_input[0..2].try_into().unwrap());
    let rc_max = u16::from_le_bytes(public_input[2..4].try_into().unwrap());
    let mem_len = u64::from_le_bytes(public_input[4..12].try_into().unwrap()) as usize;
    let mut public_memory: hashbrown::HashMap<Felt252, Felt252> = HashMap::new();
    for i in 0..mem_len {
        let start_index = 12 + i * 40;
        let addr = Felt252::from(u64::from_le_bytes(
            public_input[start_index..start_index + 8]
                .try_into()
                .unwrap(),
        ));
        let value = Felt252::from_bytes_le(
            public_input[start_index + 8..start_index + 40]
                .try_into()
                .unwrap(),
        )
        .unwrap();
        public_memory.insert(addr, value);
    }

    let memory_segments_len = public_input[12 + 40 * mem_len] as usize;
    let mut memory_segments = HashMap::new();
    for i in 0..memory_segments_len {
        let start_index = 12 + 40 * mem_len + 1 + i * 17;
        let segment_type = match public_input[start_index] {
            0u8 => SegmentName::RangeCheck,
            1u8 => SegmentName::Output,
            2u8 => SegmentName::Program,
            3u8 => SegmentName::Execution,
            4u8 => SegmentName::Ecdsa,
            5u8 => SegmentName::Pedersen,
            _ => continue, // skip unknown type
        };

        let segment_begin = u64::from_le_bytes(
            public_input[start_index + 1..start_index + 9]
                .try_into()
                .unwrap(),
        );
        let segment_stop = u64::from_le_bytes(
            public_input[start_index + 9..start_index + 17]
                .try_into()
                .unwrap(),
        );
        memory_segments.insert(segment_type, Segment::new(segment_begin, segment_stop));
    }

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
    let proof = generate_cairo_proof(&main_trace, &pub_inputs, &proof_options).unwrap();

    // Encode proof and pub_inputs
    let proof_bytes = bincode::serde::encode_to_vec(proof, bincode::config::standard()).unwrap();
    let pub_input_bytes =
        bincode::serde::encode_to_vec(&pub_inputs, bincode::config::standard()).unwrap();

    (proof_bytes, pub_input_bytes)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn cairo_verify(proof: Vec<u8>, public_input: Vec<u8>) -> bool {
    let proof_options = ProofOptions::new_secure(SecurityLevel::Conjecturable100Bits, 3);

    let (proof, _) =
        bincode::serde::decode_from_slice(&proof, bincode::config::standard()).unwrap();

    let (pub_inputs, _) =
        bincode::serde::decode_from_slice(&public_input, bincode::config::standard()).unwrap();

    verify_cairo_proof(&proof, &pub_inputs, &proof_options)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn cairo_get_compliance_output(public_input: Vec<u8>) -> NifResult<Vec<Vec<u8>>>{
    let (pub_inputs, _) : (PublicInputs, usize) =
        bincode::serde::decode_from_slice(&public_input, bincode::config::standard()).unwrap();
    let output_segments = match pub_inputs.memory_segments.get(&SegmentName::Output) {
        Some(segment) => segment,
        None => {
            eprintln!("Error: 'Output' segment not found in memory_segments");
            return Ok(vec![]);
        }
    };

    let begin_addr :u64 = output_segments.begin_addr.try_into().unwrap();
    let stop_addr :u64 = output_segments.stop_ptr.try_into().unwrap();

    let mut output_values = Vec::new();
    for addr in begin_addr..stop_addr {
        // Convert addr to FieldElement (assuming this is the correct way to create a FieldElement from an address)
        let addr_field_element = Felt252::from(addr);

        if let Some(value) = pub_inputs.public_memory.get(&addr_field_element) {
            output_values.push(value.clone().to_bytes_le().to_vec());
        } else {
            eprintln!("Error: Address {:?} not found in public memory", addr_field_element);
        }
    }
    println!("{:?}", output_values.clone());
    Ok(output_values)
}

rustler::init!("Elixir.Cairo.CairoProver", [cairo_prove, cairo_verify, cairo_get_compliance_output]);
