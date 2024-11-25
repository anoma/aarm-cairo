use lazy_static::lazy_static;

// The PLAINTEXT_NUM should be fixed to achieve the indistinguishability of resource logics
// Make it 10
pub const PLAINTEXT_NUM: usize = 10;
pub const CIPHERTEXT_MAC: usize = PLAINTEXT_NUM;
pub const CIPHERTEXT_PK_X: usize = PLAINTEXT_NUM + 1;
pub const CIPHERTEXT_PK_Y: usize = PLAINTEXT_NUM + 2;
pub const CIPHERTEXT_NONCE: usize = PLAINTEXT_NUM + 3;
pub const CIPHERTEXT_NUM: usize = PLAINTEXT_NUM + 4;

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
