use crate::error::CairoError;
use rand::{thread_rng, RngCore};
use starknet_types_core::curve::AffinePoint;
use starknet_types_core::felt::Felt;

pub fn felt_to_string(bytes: Vec<u8>) -> Result<String, CairoError> {
    let felt: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CairoError::InvalidFiniteField)?;
    Ok(Felt::from_bytes_be(&felt).to_hex_string())
}

pub fn random_felt() -> Vec<u8> {
    let mut rng = thread_rng();
    let mut felt: [u8; 32] = Default::default();
    rng.fill_bytes(&mut felt);
    let felt = Felt::from_bytes_be_slice(&felt);
    felt.to_bytes_be().to_vec()
}

pub fn bytes_to_felt_vec(bytes: Vec<Vec<u8>>) -> Result<Vec<Felt>, CairoError> {
    let mut vec_fe = Vec::new();
    for i in bytes {
        let i_bytes: [u8; 32] = i
            .as_slice()
            .try_into()
            .map_err(|_| CairoError::InvalidFiniteField)?;
        vec_fe.push(Felt::from_bytes_be(&i_bytes))
    }

    Ok(vec_fe)
}

pub fn bytes_to_felt(bytes: Vec<u8>) -> Result<Felt, CairoError> {
    let felt: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CairoError::InvalidFiniteField)?;

    Ok(Felt::from_bytes_be(&felt))
}

pub fn bytes_to_affine(bytes: Vec<u8>) -> Result<AffinePoint, CairoError> {
    if bytes.len() != 64 {
        return Err(CairoError::InvalidAffinePoint);
    }

    let (x, y) = bytes.split_at(32);
    let key_x = bytes_to_felt(x.to_vec())?;
    let key_y = bytes_to_felt(y.to_vec())?;

    AffinePoint::new(key_x, key_y).map_err(|_| CairoError::InvalidAffinePoint)
}
