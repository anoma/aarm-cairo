mod errors;

use crate::errors::{
    CairoBindingSigError, CairoBindingSigVerifyError, CairoGetOutputError, CairoProveError,
    CairoSignError, CairoVerifyError,
};
use cairo_platinum_prover::{
    air::{generate_cairo_proof, verify_cairo_proof, PublicInputs, Segment, SegmentName},
    cairo_mem::CairoMemory,
    execution_trace::build_main_trace,
    register_states::RegisterStates,
    Felt252,
};
use hashbrown::HashMap;
use lambdaworks_math::traits::ByteConversion;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::Zero;
use rand::{thread_rng, RngCore};
use rustler::{Error, NifResult};
use stark_platinum_prover::proof::options::{ProofOptions, SecurityLevel};
use starknet_crypto::{poseidon_hash, poseidon_hash_many, poseidon_hash_single, sign, verify};
use starknet_curve::curve_params::{EC_ORDER, GENERATOR};
use starknet_types_core::{
    curve::{AffinePoint, ProjectivePoint},
    felt::Felt,
};
use std::ops::Add;

#[rustler::nif(schedule = "DirtyCpu")]
fn cairo_prove(
    trace: Vec<u8>,
    memory: Vec<u8>,
    public_input: Vec<u8>,
) -> NifResult<(Vec<u8>, Vec<u8>)> {
    // Generating the prover args
    let register_states = RegisterStates::from_bytes_le(&trace).map_err(|e| {
        Error::Term(Box::new(CairoProveError::RegisterStatesError(format!(
            "{:?}",
            e
        ))))
    })?;

    let memory = CairoMemory::from_bytes_le(&memory).map_err(|e| {
        Error::Term(Box::new(CairoProveError::CairoMemoryError(format!(
            "{:?}",
            e
        ))))
    })?;

    // Handle public inputs
    let (rc_min, rc_max, public_memory, memory_segments) = parse_public_input(&public_input)
        .map_err(|e| Error::Term(Box::new(CairoProveError::PublicInputError(e.to_string()))))?;

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
    let proof = generate_cairo_proof(&main_trace, &pub_inputs, &proof_options).map_err(|e| {
        Error::Term(Box::new(CairoProveError::ProofGenerationError(format!(
            "{:?}",
            e
        ))))
    })?;

    // Encode proof and pub_inputs
    let proof_bytes = bincode::serde::encode_to_vec(proof, bincode::config::standard())
        .map_err(|e| Error::Term(Box::new(CairoProveError::EncodingError(format!("{:?}", e)))))?;
    let pub_input_bytes = bincode::serde::encode_to_vec(&pub_inputs, bincode::config::standard())
        .map_err(|e| {
        Error::Term(Box::new(CairoProveError::EncodingError(format!("{:?}", e))))
    })?;

    Ok((proof_bytes, pub_input_bytes))
}

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
                .ok_or("Input too short for public memory value")?
                .try_into()
                .map_err(|_| "Failed to convert public memory value bytes")?,
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

#[rustler::nif(schedule = "DirtyCpu")]
fn cairo_verify(proof: Vec<u8>, public_input: Vec<u8>) -> NifResult<bool> {
    let proof_options = ProofOptions::new_secure(SecurityLevel::Conjecturable100Bits, 3);

    // Decode proof
    let proof = bincode::serde::decode_from_slice(&proof, bincode::config::standard())
        .map_err(|e| {
            Error::Term(Box::new(CairoVerifyError::ProofDecodingError(
                e.to_string(),
            )))
        })?
        .0;

    // Decode public inputs
    let pub_inputs = bincode::serde::decode_from_slice(&public_input, bincode::config::standard())
        .map_err(|e| {
            Error::Term(Box::new(CairoVerifyError::PublicInputDecodingError(
                e.to_string(),
            )))
        })?
        .0;

    Ok(verify_cairo_proof(&proof, &pub_inputs, &proof_options))
}

#[rustler::nif()]
fn cairo_get_output(public_input: Vec<u8>) -> NifResult<Vec<Vec<u8>>> {
    // Decode public inputs
    let (pub_inputs, _): (PublicInputs, usize) =
        bincode::serde::decode_from_slice(&public_input, bincode::config::standard()).map_err(
            |e| Error::Term(Box::new(CairoGetOutputError::DecodingError(e.to_string()))),
        )?;

    // Get output segments
    let output_segments = pub_inputs
        .memory_segments
        .get(&SegmentName::Output)
        .ok_or_else(|| Error::Term(Box::new(CairoGetOutputError::SegmentNotFound)))?;

    let begin_addr: u64 = output_segments.begin_addr as u64;
    let stop_addr: u64 = output_segments.stop_ptr as u64;

    let mut output_values = Vec::new();
    for addr in begin_addr..stop_addr {
        // Convert addr to FieldElement (assuming this is the correct way to create a FieldElement from an address)
        let addr_field_element = Felt252::from(addr);

        if let Some(value) = pub_inputs.public_memory.get(&addr_field_element) {
            output_values.push(value.clone().to_bytes_be().to_vec());
        } else {
            return Err(Error::Term(Box::new(CairoGetOutputError::AddressNotFound(
                addr,
            ))));
        }
    }

    Ok(output_values)
}

// The private_key_segments are random values used in delta commitments.
// The messages are nullifiers and resource commitments in the transaction.
#[rustler::nif]
fn cairo_binding_sig_sign(
    private_key_segments: Vec<u8>,
    messages: Vec<Vec<u8>>,
) -> NifResult<Vec<u8>> {
    // Compute private key
    let private_key = {
        let result = private_key_segments
            .chunks(32)
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
    let sig_hash = message_digest(messages)?;

    // ECDSA sign
    let mut rng = thread_rng();
    let k = {
        let mut felt: [u8; 32] = Default::default();
        rng.fill_bytes(&mut felt);
        Felt::from_bytes_be(&felt)
    };
    let signature = sign(&private_key, &sig_hash, &k).map_err(|e| {
        Error::Term(Box::new(CairoSignError::SignatureGenerationError(
            e.to_string(),
        )))
    })?;

    // Serialize signature
    let mut ret = Vec::new();
    ret.extend(signature.r.to_bytes_be());
    ret.extend(signature.s.to_bytes_be());
    // We don't need the v to recover pubkey
    // ret.extend(signature.v.to_bytes_be());
    Ok(ret)
}

// The pub_key_segments are delta commitments in compliance input inputs.
#[rustler::nif]
fn cairo_binding_sig_verify(
    pub_key_segments: Vec<Vec<u8>>,
    messages: Vec<Vec<u8>>,
    signature: Vec<u8>,
) -> NifResult<bool> {
    // Generate the public key
    let pub_key = pub_key_segments
        .into_iter()
        .try_fold(ProjectivePoint::identity(), |acc, bytes| {
            let key_x = Felt::from_bytes_be(
                &bytes[0..32]
                    .try_into()
                    .map_err(|_| CairoBindingSigVerifyError::InputError)?,
            );
            let key_y = Felt::from_bytes_be(
                &bytes[32..64]
                    .try_into()
                    .map_err(|_| CairoBindingSigVerifyError::InputError)?,
            );
            let key_segment_affine = AffinePoint::new(key_x, key_y)
                .map_err(|_| CairoBindingSigVerifyError::InputError)?;
            Ok(acc.add(key_segment_affine))
        })
        .map_err(|e: CairoBindingSigVerifyError| Error::Term(Box::new(e)))?
        .to_affine()
        .map_err(|_| Error::Term(Box::new(CairoBindingSigVerifyError::InputError)))?
        .x();

    // Message digest
    let msg = message_digest(messages)?;

    // Decode the signature
    let r = Felt::from_bytes_be(
        signature[0..32]
            .try_into()
            .map_err(|_| Error::Term(Box::new(CairoBindingSigVerifyError::InputError)))?,
    );
    let s = Felt::from_bytes_be(
        signature[32..64]
            .try_into()
            .map_err(|_| Error::Term(Box::new(CairoBindingSigVerifyError::InputError)))?,
    );

    // Verify the signature
    verify(&pub_key, &msg, &r, &s)
        .map_err(|_| Error::Term(Box::new(CairoBindingSigVerifyError::VerificationError)))
}

// random_felt can help create private key in signature
#[rustler::nif]
fn cairo_random_felt() -> NifResult<Vec<u8>> {
    let mut rng = thread_rng();
    let mut felt: [u8; 32] = Default::default();
    rng.fill_bytes(&mut felt);
    let felt = Felt::from_bytes_be_slice(&felt);
    Ok(felt.to_bytes_be().to_vec())
}

#[rustler::nif]
fn cairo_get_binding_sig_public_key(priv_key: Vec<u8>) -> NifResult<Vec<u8>> {
    let priv_key_felt = Felt::from_bytes_be_slice(&priv_key);

    let generator = ProjectivePoint::from_affine(GENERATOR.x(), GENERATOR.y())
        .map_err(|_| Error::Term(Box::new(CairoBindingSigError::KeyGenerationError)))?;

    let pub_key = (&generator * priv_key_felt)
        .to_affine()
        .map_err(|_| Error::Term(Box::new(CairoBindingSigError::KeyGenerationError)))?;

    let mut ret = pub_key.x().to_bytes_be().to_vec();
    let mut y = pub_key.y().to_bytes_be().to_vec();
    ret.append(&mut y);
    Ok(ret)
}
fn message_digest(msg: Vec<Vec<u8>>) -> NifResult<Felt> {
    let felt_msg_vec: Vec<Felt> = msg
        .into_iter()
        .map(|bytes| Felt::from_bytes_be(&bytes.try_into().expect("Slice with incorrect length")))
        .collect();
    Ok(poseidon_hash_many(&felt_msg_vec))
}

#[rustler::nif]
fn poseidon_single(x: Vec<u8>) -> NifResult<Vec<u8>> {
    let mut padded_x = x;
    padded_x.resize(32, 0);
    let x_bytes: [u8; 32] = padded_x
        .as_slice()
        .try_into()
        .expect("Slice with incorrect length");
    let x_field = Felt::from_bytes_be(&x_bytes);
    Ok(poseidon_hash_single(x_field).to_bytes_be().to_vec())
}

#[rustler::nif]
fn poseidon(x: Vec<u8>, y: Vec<u8>) -> NifResult<Vec<u8>> {
    let x_bytes: [u8; 32] = x
        .as_slice()
        .try_into()
        .expect("Slice with incorrect length");
    let x_field = Felt::from_bytes_be(&x_bytes);
    let y_bytes: [u8; 32] = y
        .as_slice()
        .try_into()
        .expect("Slice with incorrect length");
    let y_field = Felt::from_bytes_be(&y_bytes);
    Ok(poseidon_hash(x_field, y_field).to_bytes_be().to_vec())
}

#[rustler::nif]
fn poseidon_many(inputs: Vec<Vec<u8>>) -> NifResult<Vec<u8>> {
    let mut vec_fe = Vec::new();
    for i in inputs {
        let i_bytes: [u8; 32] = i
            .as_slice()
            .try_into()
            .expect("Slice with incorrect length");
        vec_fe.push(Felt::from_bytes_be(&i_bytes))
    }
    let result_fe = poseidon_hash_many(&vec_fe);
    Ok(result_fe.to_bytes_be().to_vec())
}

// Get the program from public inputs and return the program hash as the
// resource label
#[rustler::nif]
fn program_hash(public_inputs: Vec<u8>) -> NifResult<Vec<u8>> {
    let (pub_inputs, _): (PublicInputs, usize) =
        bincode::serde::decode_from_slice(&public_inputs, bincode::config::standard()).unwrap();
    let program_segments = match pub_inputs.memory_segments.get(&SegmentName::Program) {
        Some(segment) => segment,
        None => {
            eprintln!("Error: 'Program' segment not found in memory_segments");
            return Ok(vec![]);
        }
    };

    let begin_addr: u64 = program_segments.begin_addr as u64;
    let stop_addr: u64 = program_segments.stop_ptr as u64;

    let mut program = Vec::new();
    for addr in begin_addr..stop_addr {
        // Convert addr to FieldElement (assuming this is the correct way to create a FieldElement from an address)
        let addr_field_element = Felt252::from(addr);

        if let Some(value) = pub_inputs.public_memory.get(&addr_field_element) {
            program.push(Felt::from_raw(value.to_raw().limbs));
        } else {
            eprintln!(
                "Error: Address {:?} not found in public memory",
                addr_field_element
            );
            return Ok(vec![]);
        }
    }

    let program_hash = poseidon_hash_many(&program);

    Ok(program_hash.to_bytes_be().to_vec())
}

#[rustler::nif]
fn felt_to_string(felt: Vec<u8>) -> String {
    Felt::from_bytes_be(
        felt.as_slice()
            .try_into()
            .expect("Slice with incorrect length"),
    )
    .to_hex_string()
}

rustler::init!(
    "Elixir.Cairo.CairoProver",
    [
        cairo_prove,
        cairo_verify,
        cairo_get_output,
        cairo_binding_sig_sign,
        cairo_binding_sig_verify,
        cairo_random_felt,
        cairo_get_binding_sig_public_key,
        poseidon_single,
        poseidon,
        poseidon_many,
        program_hash,
        felt_to_string,
    ]
);

use lazy_static::lazy_static;
lazy_static! {
    // Bytes: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 67, 97, 105, 114, 111, 95, 69, 120, 112, 97, 110, 100, 83, 101, 101, 100]
    // Hexstring: "0x436169726f5f457870616e6453656564"
    // Decimal string(used in juvix): "89564067232354163924078705540990330212"
    pub static ref PRF_EXPAND_PERSONALIZATION_FELT: Vec<u8> = {
        let personalization: Vec<u8> = b"Cairo_ExpandSeed".to_vec();
        let mut result = [0u8; 32];
        result[(32 - personalization.len())..].copy_from_slice(&personalization[..]);

        result.to_vec()
    };
}

#[test]
fn test_prf_expand_personalization() {
    println!(
        "PRF_EXPAND_PERSONALIZATION_FELT bytes: {:?}",
        *PRF_EXPAND_PERSONALIZATION_FELT
    );

    println!(
        "hex: {:?}",
        Felt::from_bytes_be(
            &PRF_EXPAND_PERSONALIZATION_FELT
                .as_slice()
                .try_into()
                .unwrap()
        )
        .to_hex_string()
    );
}

#[test]
fn generate_compliance_input_test_params() {
    println!("Felf one hex: {:?}", Felt::ONE.to_hex_string());
    let input_nf_key = Felt::ONE;
    let input_npk = poseidon_hash(input_nf_key, Felt::ZERO);
    println!("input_npk: {:?}", input_npk.to_hex_string());
}
