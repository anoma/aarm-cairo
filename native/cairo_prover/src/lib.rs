#![allow(dead_code)]

mod binding_signature;
mod compliance_input;
mod constants;
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
