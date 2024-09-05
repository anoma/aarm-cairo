use rand::{thread_rng, RngCore};
use starknet_types_core::felt::Felt;

pub fn felt_to_string(felt: &Vec<u8>) -> String {
    assert_eq!(felt.len(), 32, "The felt size is not 32 bytes");
    Felt::from_bytes_be(
        felt.as_slice()
            .try_into()
            .expect("Slice with incorrect length"),
    )
    .to_hex_string()
}

pub fn random_felt() -> Vec<u8> {
    let mut rng = thread_rng();
    let mut felt: [u8; 32] = Default::default();
    rng.fill_bytes(&mut felt);
    let felt = Felt::from_bytes_be_slice(&felt);
    felt.to_bytes_be().to_vec()
}
