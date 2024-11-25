use crate::{
    error::CairoError,
    utils::{bytes_to_affine, bytes_to_felt, bytes_to_felt_vec},
};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::Zero;
use rand::{thread_rng, RngCore};
use rustler::NifResult;
use starknet_crypto::{poseidon_hash_many, sign, verify};
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
