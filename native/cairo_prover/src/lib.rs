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
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::Zero;
use rand::{thread_rng, RngCore};
use stark_platinum_prover::proof::options::{ProofOptions, SecurityLevel};
use starknet_crypto::{poseidon_hash_many, sign, verify};
use starknet_curve::curve_params::{EC_ORDER, GENERATOR};
use starknet_types_core::{
    curve::{AffinePoint, ProjectivePoint},
    felt::Felt,
};
use std::ops::Add;

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

#[rustler::nif()]
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
    Ok(output_values)
}

// The private_key_segments are random values used in delta commitments.
// The messages are nullifiers and resource commitments in the transaction.
#[rustler::nif]
fn cairo_binding_sig_sign(private_key_segments: Vec<Vec<u8>>, messages: Vec<Vec<u8>>) -> Vec<u8> {
    // Compute private key
    let private_key = {
        let result = private_key_segments
            .iter()
            .fold(BigInt::zero(), |acc, key_segment| {
                let key = BigInt::from_bytes_be(num_bigint::Sign::Plus, &key_segment);
                acc.add(key)
            })
            .mod_floor(&EC_ORDER.to_bigint());

        let (_, buffer) = result.to_bytes_be();
        let mut result = [0u8; 32];
        result[(32 - buffer.len())..].copy_from_slice(&buffer[..]);

        Felt::from_bytes_be(&result)
    };

    // Message digest
    let sig_hash = message_digest(messages);

    // ECDSA sign
    let mut rng = thread_rng();
    let k = {
        let mut felt: [u8; 32] = Default::default();
        rng.fill_bytes(&mut felt);
        Felt::from_bytes_be(&felt)
    };
    let signature = sign(&private_key, &sig_hash, &k).unwrap();

    // Serialize signature
    let mut ret = Vec::new();
    ret.extend(signature.r.to_bytes_be());
    ret.extend(signature.s.to_bytes_be());
    // We don't need the v to recover pubkey
    // ret.extend(signature.v.to_bytes_be());
    ret
}

// The pub_key_segments are delta commitments in compliance input inputs.
#[rustler::nif]
fn cairo_binding_sig_verify(
    pub_key_segments: Vec<Vec<u8>>,
    messages: Vec<Vec<u8>>,
    signature: Vec<u8>,
) -> bool {
    // Generate the public key
    let pub_key = pub_key_segments
        .into_iter()
        .fold(ProjectivePoint::identity(), |acc, bytes| {
            let key_x = Felt::from_bytes_be(
                &bytes[0..32]
                    .try_into()
                    .expect("Slice with incorrect length"),
            );
            let key_y = Felt::from_bytes_be(
                &bytes[32..64]
                    .try_into()
                    .expect("Slice with incorrect length"),
            );
            let key_segment_affine = AffinePoint::new(key_x, key_y).unwrap();
            acc.add(key_segment_affine)
        })
        .to_affine()
        .unwrap()
        .x();

    // Message digest
    let msg = message_digest(messages);

    // Decode the signature
    let r = Felt::from_bytes_be(
        &signature[0..32]
            .try_into()
            .expect("Slice with incorrect length"),
    );
    let s = Felt::from_bytes_be(
        &signature[32..64]
            .try_into()
            .expect("Slice with incorrect length"),
    );

    // Verify the signature
    verify(&pub_key, &msg, &r, &s).unwrap()
}

fn message_digest(msg: Vec<Vec<u8>>) -> Felt {
    let felt_msg_vec: Vec<Felt> = msg
        .into_iter()
        .map(|bytes| Felt::from_bytes_be(&bytes.try_into().expect("Slice with incorrect length")))
        .collect();
    poseidon_hash_many(&felt_msg_vec)
}

rustler::init!(
    "Elixir.Cairo.CairoProver",
    [
        cairo_prove,
        cairo_verify,
        cairo_get_compliance_output,
        cairo_binding_sig_sign,
        cairo_binding_sig_verify
    ]
);
