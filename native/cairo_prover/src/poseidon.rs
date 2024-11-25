use crate::utils::{bytes_to_felt, bytes_to_felt_vec};
use rustler::NifResult;
use starknet_crypto::{poseidon_hash, poseidon_hash_many, poseidon_hash_single};

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
