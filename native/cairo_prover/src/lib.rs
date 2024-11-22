#![allow(dead_code)]

mod binding_signature;
mod compliance_input;
mod encryption;
mod error;
mod poseidon;
mod prover;
mod utils;
mod verifier;

use crate::{
    compliance_input::ComplianceInputJson,
    encryption::Ciphertext,
    utils::{bytes_to_affine, bytes_to_felt, bytes_to_felt_vec},
};
use rustler::NifResult;

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
        binding_signature::cairo_binding_sig_sign,
        binding_signature::cairo_binding_sig_verify,
        binding_signature::get_public_key,
        poseidon::poseidon_single,
        poseidon::poseidon,
        poseidon::poseidon_many,
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
    use starknet_types_core::felt::Felt;
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
    use starknet_crypto::poseidon_hash;
    use starknet_types_core::felt::Felt;

    println!("Felf one hex: {:?}", Felt::ONE.to_hex_string());
    let input_nf_key = Felt::ONE;
    let input_npk = poseidon_hash(input_nf_key, Felt::ZERO);
    println!("input_npk: {:?}", input_npk.to_bytes_be());
    println!("input_npk: {:?}", input_npk.to_hex_string());
}
