use starknet_crypto::{poseidon_hash, poseidon_hash_many};
use starknet_curve::curve_params::GENERATOR;
use starknet_types_core::{
    curve::{AffinePoint, ProjectivePoint},
    felt::Felt,
};

// The PLAINTEXT_NUM should be fixed to achieve the indistinguishability of resource logics
// Make it 10
pub const PLAINTEXT_NUM: usize = 10;
pub const CIPHERTEXT_MAC: usize = PLAINTEXT_NUM;
pub const CIPHERTEXT_PK_X: usize = PLAINTEXT_NUM + 1;
pub const CIPHERTEXT_PK_Y: usize = PLAINTEXT_NUM + 2;
pub const CIPHERTEXT_NONCE: usize = PLAINTEXT_NUM + 3;
pub const CIPHERTEXT_NUM: usize = PLAINTEXT_NUM + 4;

#[derive(Debug, Clone)]
pub struct Ciphertext([Felt; CIPHERTEXT_NUM]);

#[derive(Debug, Clone)]
pub struct Plaintext([Felt; PLAINTEXT_NUM]);

// Symmetric encryption key
#[derive(Debug, Clone)]
pub struct SecretKey(AffinePoint);

impl Ciphertext {
    pub fn inner(&self) -> &[Felt; CIPHERTEXT_NUM] {
        &self.0
    }

    pub fn encrypt(messages: &[Felt], pk: &AffinePoint, sk: &Felt, encrypt_nonce: &Felt) -> Self {
        // Generate the secret key
        let (secret_key_x, secret_key_y) = SecretKey::from_dh_exchange(pk, sk).get_coordinates();

        // Pad the messages
        let plaintext = Plaintext::padding(messages);

        // Init poseidon state
        let mut poseidon_state = poseidon_hash_many(&vec![
            secret_key_x,
            secret_key_y,
            *encrypt_nonce,
            Felt::from(PLAINTEXT_NUM),
        ]);

        // Encrypt
        let mut cipher = vec![];
        plaintext.inner().iter().for_each(|f| {
            poseidon_state += f;
            cipher.push(poseidon_state);
            poseidon_state = poseidon_hash(poseidon_state, secret_key_x);
        });

        // Add MAC
        cipher.push(poseidon_state);

        // Add sender's public key
        let generator = ProjectivePoint::from_affine(GENERATOR.x(), GENERATOR.y()).unwrap();
        let sender_pk = (&generator * *sk).to_affine().unwrap();
        cipher.push(sender_pk.x());
        cipher.push(sender_pk.y());

        // Add encrypt_nonce
        cipher.push(*encrypt_nonce);

        cipher.into()
    }

    pub fn decrypt(&self, sk: &Felt) -> Option<Vec<Felt>> {
        let cipher_text = self.inner();
        let cipher_len = cipher_text.len();
        if cipher_len != CIPHERTEXT_NUM {
            return None;
        }

        let mac = cipher_text[CIPHERTEXT_MAC];
        let pk_x = cipher_text[CIPHERTEXT_PK_X];
        let pk_y = cipher_text[CIPHERTEXT_PK_Y];
        let encrypt_nonce = cipher_text[CIPHERTEXT_NONCE];

        if let Ok(pk) = AffinePoint::new(pk_x, pk_y) {
            // Generate the secret key
            let (secret_key_x, secret_key_y) =
                SecretKey::from_dh_exchange(&pk, sk).get_coordinates();

            // Init poseidon sponge state
            let mut poseidon_state = poseidon_hash_many(&vec![
                secret_key_x,
                secret_key_y,
                encrypt_nonce,
                Felt::from(PLAINTEXT_NUM),
            ]);

            // Decrypt
            let mut msg = vec![];
            for cipher_element in &cipher_text[0..PLAINTEXT_NUM] {
                let msg_element = *cipher_element - poseidon_state;
                msg.push(msg_element);
                poseidon_state = poseidon_hash(*cipher_element, secret_key_x);
            }

            if mac != poseidon_state {
                return None;
            }

            Some(msg)
        } else {
            return None;
        }
    }
}

impl From<Vec<Felt>> for Ciphertext {
    fn from(input_vec: Vec<Felt>) -> Self {
        Ciphertext(
            input_vec
                .try_into()
                .expect("public input with incorrect length"),
        )
    }
}

impl Plaintext {
    pub fn inner(&self) -> &[Felt; PLAINTEXT_NUM] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<Felt> {
        self.0.to_vec()
    }

    pub fn padding(msg: &[Felt]) -> Self {
        let mut plaintext = msg.to_owned();
        let padding = std::iter::repeat(Felt::ZERO).take(PLAINTEXT_NUM - msg.len());
        plaintext.extend(padding);
        plaintext.into()
    }
}

impl From<Vec<Felt>> for Plaintext {
    fn from(input_vec: Vec<Felt>) -> Self {
        Plaintext(
            input_vec
                .try_into()
                .expect("public input with incorrect length"),
        )
    }
}

impl SecretKey {
    pub fn from_dh_exchange(pk: &AffinePoint, sk: &Felt) -> Self {
        Self(
            (&ProjectivePoint::try_from(pk.clone()).unwrap() * *sk)
                .to_affine()
                .unwrap(),
        )
    }

    pub fn get_coordinates(&self) -> (Felt, Felt) {
        (self.0.x(), self.0.y())
    }
}

#[test]
fn test_encryption() {
    // Key generation
    let sender_sk = Felt::ONE;
    let pk = GENERATOR;

    // let key = SecretKey::from_dh_exchange(pk, random_sk);
    let messages = [Felt::ONE, Felt::ZERO, Felt::ONE];
    let encrypt_nonce = Felt::ONE;

    // Encryption
    let cipher = Ciphertext::encrypt(&messages, &pk, &sender_sk, &encrypt_nonce);

    // Decryption
    let decryption = cipher.decrypt(&Felt::ONE).unwrap();

    let padded_plaintext = Plaintext::padding(&messages);
    assert_eq!(padded_plaintext.to_vec(), decryption);
}
