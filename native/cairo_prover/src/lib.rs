use cairo_platinum_prover::{
    air::{generate_cairo_proof, verify_cairo_proof, PublicInputs},
    cairo_mem::CairoMemory,
    execution_trace::build_main_trace,
    register_states::RegisterStates,
    Felt252,
};
use hashbrown::HashMap;
use lambdaworks_math::traits::ByteConversion;
use stark_platinum_prover::proof::options::{ProofOptions, SecurityLevel};

#[rustler::nif(schedule = "DirtyCpu")]
fn cairo_prove(trace: Vec<u8>, memory: Vec<u8>, public_input: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    // Generating the prover args
    let register_states = RegisterStates::from_bytes_le(&trace).unwrap();
    let memory = CairoMemory::from_bytes_le(&memory).unwrap();

    // Handle public inputs
    let rc_min = u16::from_le_bytes(public_input[0..2].try_into().unwrap());
    let rc_max = u16::from_le_bytes(public_input[2..4].try_into().unwrap());
    let mem_len = u64::from_le_bytes(public_input[4..12].try_into().unwrap());
    let mut public_memory: hashbrown::HashMap<Felt252, Felt252> = HashMap::new();
    for i in 0..mem_len {
        let start_index = (12 + i * 40) as usize;
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

    let num_steps = register_states.steps();
    let mut pub_inputs = PublicInputs {
        pc_init: Felt252::from(register_states.rows[0].pc),
        ap_init: Felt252::from(register_states.rows[0].ap),
        fp_init: Felt252::from(register_states.rows[0].fp),
        pc_final: Felt252::from(register_states.rows[num_steps - 1].pc),
        ap_final: Felt252::from(register_states.rows[num_steps - 1].ap),
        range_check_min: Some(rc_min),
        range_check_max: Some(rc_max),
        memory_segments: HashMap::new(),
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

rustler::init!("Elixir.Cairo.CairoProver", [cairo_prove, cairo_verify]);
