#![allow(dead_code)]

mod compliance_input;
mod encryption;
mod error;
mod prover;
mod utils;
mod verifier;

use crate::{
    compliance_input::ComplianceInputJson,
    encryption::Ciphertext,
    error::CairoError,
    utils::{bytes_to_affine, bytes_to_felt, bytes_to_felt_vec},
};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::Zero;
use rand::{thread_rng, RngCore};
use rustler::NifResult;
use starknet_crypto::{poseidon_hash, poseidon_hash_many, poseidon_hash_single, sign, verify};
use starknet_curve::curve_params::{EC_ORDER, GENERATOR};
use starknet_types_core::{curve::ProjectivePoint, felt::Felt};
use std::ops::Add;

// The private_key_segments are random values used in delta commitments.
// The messages are nullifiers and resource commitments in the transaction.
#[rustler::nif]
fn cairo_binding_sig_sign(
    private_key_segments: Vec<u8>,
    messages: Vec<Vec<u8>>,
) -> NifResult<Vec<u8>> {
    if private_key_segments.is_empty() || private_key_segments.len() % 32 != 0 {
        return Err(CairoError::InvalidInputs.into());
    }
    // Compute private key
    let private_key = {
        let result = private_key_segments
            .chunks(32)
            .fold(BigInt::zero(), |acc, key_segment| {
                let key = BigInt::from_bytes_be(num_bigint::Sign::Plus, key_segment);
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
    let signature = sign(&private_key, &sig_hash, &k).map_err(CairoError::from)?;

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
    let mut pub_key = ProjectivePoint::identity();
    for pk_seg_bytes in pub_key_segments.into_iter() {
        let pk_seg = bytes_to_affine(pk_seg_bytes)?;
        pub_key += pk_seg;
    }
    let pub_key_x = pub_key
        .to_affine()
        .map_err(|_| CairoError::InvalidAffinePoint)?
        .x();

    // Message digest
    let msg = message_digest(messages)?;

    // Decode the signature
    if signature.len() != 64 {
        return Err(CairoError::InvalidSignatureFormat.into());
    }

    let (r_bytes, s_bytes) = signature.split_at(32);
    let r = bytes_to_felt(r_bytes.to_vec())?;
    let s = bytes_to_felt(s_bytes.to_vec())?;

    // Verify the signature
    verify(&pub_key_x, &msg, &r, &s).map_err(|_| CairoError::SigVerifyError.into())
}

#[rustler::nif]
fn get_public_key(priv_key: Vec<u8>) -> NifResult<Vec<u8>> {
    let priv_key_felt = bytes_to_felt(priv_key)?;

    let generator = ProjectivePoint::from_affine(GENERATOR.x(), GENERATOR.y())
        .map_err(|_| CairoError::InvalidAffinePoint)?;

    let pub_key = (&generator * priv_key_felt)
        .to_affine()
        .map_err(|_| CairoError::InvalidAffinePoint)?;

    let mut ret = pub_key.x().to_bytes_be().to_vec();
    let mut y = pub_key.y().to_bytes_be().to_vec();
    ret.append(&mut y);
    Ok(ret)
}
fn message_digest(msg: Vec<Vec<u8>>) -> NifResult<Felt> {
    let felt_msg_vec: Vec<Felt> = bytes_to_felt_vec(msg)?;
    Ok(poseidon_hash_many(&felt_msg_vec))
}

#[rustler::nif]
fn poseidon_single(x: Vec<u8>) -> NifResult<Vec<u8>> {
    let x_field = bytes_to_felt(x)?;
    Ok(poseidon_hash_single(x_field).to_bytes_be().to_vec())
}

#[rustler::nif]
fn poseidon(x: Vec<u8>, y: Vec<u8>) -> NifResult<Vec<u8>> {
    let x_field = bytes_to_felt(x)?;
    let y_field = bytes_to_felt(y)?;
    Ok(poseidon_hash(x_field, y_field).to_bytes_be().to_vec())
}

#[rustler::nif]
fn poseidon_many(inputs: Vec<Vec<u8>>) -> NifResult<Vec<u8>> {
    let vec_fe = bytes_to_felt_vec(inputs)?;
    let result_fe = poseidon_hash_many(&vec_fe);
    Ok(result_fe.to_bytes_be().to_vec())
}

#[rustler::nif]
fn cairo_generate_compliance_input_json(
    input_resource: Vec<u8>,
    output_resource: Vec<u8>,
    path: Vec<Vec<u8>>,
    pos: u64,
    input_nf_key: Vec<u8>,
    eph_root: Vec<u8>,
    rcv: Vec<u8>,
) -> NifResult<String> {
    Ok(ComplianceInputJson::to_json_string(
        input_resource,
        output_resource,
        path,
        pos,
        input_nf_key,
        eph_root,
        rcv,
    )?)
}

#[rustler::nif]
fn encrypt(
    messages: Vec<Vec<u8>>,
    pk: Vec<u8>,
    sk: Vec<u8>,
    nonce: Vec<u8>,
) -> NifResult<Vec<Vec<u8>>> {
    // Decode messages
    let msgs_felt = bytes_to_felt_vec(messages)?;

    // Decode pk
    let pk_affine = bytes_to_affine(pk)?;

    // Decode sk
    let sk_felt = bytes_to_felt(sk)?;

    // Decode nonce
    let nonce_felt = bytes_to_felt(nonce)?;

    // Encrypt
    let cipher = Ciphertext::encrypt(&msgs_felt, &pk_affine, &sk_felt, &nonce_felt)?;
    let cipher_bytes = cipher
        .inner()
        .iter()
        .map(|x| x.to_bytes_be().to_vec())
        .collect();

    Ok(cipher_bytes)
}

#[rustler::nif]
fn decrypt(cihper: Vec<Vec<u8>>, sk: Vec<u8>) -> NifResult<Vec<Vec<u8>>> {
    // Decode messages
    let cipher = Ciphertext::from_bytes(cihper)?;

    // Decode sk
    let sk_felt = bytes_to_felt(sk)?;

    // Encrypt
    let plaintext = cipher.decrypt(&sk_felt)?;
    let plaintext_bytes = plaintext.iter().map(|x| x.to_bytes_be().to_vec()).collect();

    Ok(plaintext_bytes)
}

rustler::init!(
    "Elixir.Cairo.CairoProver",
    [
        prover::cairo_prove,
        verifier::cairo_verify,
        verifier::cairo_get_output,
        verifier::program_hash,
        cairo_binding_sig_sign,
        cairo_binding_sig_verify,
        get_public_key,
        poseidon_single,
        poseidon,
        poseidon_many,
        utils::cairo_random_felt,
        utils::cairo_felt_to_string,
        cairo_generate_compliance_input_json,
        encrypt,
        decrypt,
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
    println!("input_npk: {:?}", input_npk.to_bytes_be());
    println!("input_npk: {:?}", input_npk.to_hex_string());
}
