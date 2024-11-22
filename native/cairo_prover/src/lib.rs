#![allow(dead_code)]

mod binding_signature;
mod compliance_input;
mod encryption;
mod error;
mod poseidon;
mod prover;
mod utils;
mod verifier;

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
        compliance_input::cairo_generate_compliance_input_json,
        encryption::encrypt,
        encryption::decrypt,
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
