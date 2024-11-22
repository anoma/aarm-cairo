use crate::{
    constants::{
        CIPHERTEXT_MAC, CIPHERTEXT_NONCE, CIPHERTEXT_NUM, CIPHERTEXT_PK_X, CIPHERTEXT_PK_Y,
        PLAINTEXT_NUM,
    },
    error::CairoError,
    utils::{bytes_to_affine, bytes_to_felt, bytes_to_felt_vec},
};
use rustler::NifResult;
use starknet_crypto::{poseidon_hash, poseidon_hash_many};
use starknet_curve::curve_params::GENERATOR;
use starknet_types_core::{
    curve::{AffinePoint, ProjectivePoint},
    felt::Felt,
};

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

    pub fn encrypt(
        messages: &[Felt],
        pk: &AffinePoint,
        sk: &Felt,
        encrypt_nonce: &Felt,
    ) -> Result<Self, CairoError> {
        // Generate the secret key
        let secret_key = SecretKey::from_dh_exchange(pk, sk)?;
        let (secret_key_x, secret_key_y) = secret_key.get_coordinates();

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
        let generator = ProjectivePoint::from_affine(GENERATOR.x(), GENERATOR.y())
            .map_err(|_| CairoError::InvalidAffinePoint)?;
        let sender_pk = (&generator * *sk)
            .to_affine()
            .map_err(|_| CairoError::InvalidAffinePoint)?;
        cipher.push(sender_pk.x());
        cipher.push(sender_pk.y());

        // Add encrypt_nonce
        cipher.push(*encrypt_nonce);

        let ret: [Felt; CIPHERTEXT_NUM] = cipher
            .try_into()
            .map_err(|_| CairoError::InvalidCiphertextLength)?;

        Ok(Self(ret))
    }

    pub fn decrypt(&self, sk: &Felt) -> Result<Vec<Felt>, CairoError> {
        let mac = self.inner()[CIPHERTEXT_MAC];
        let pk_x = self.inner()[CIPHERTEXT_PK_X];
        let pk_y = self.inner()[CIPHERTEXT_PK_Y];
        let encrypt_nonce = self.inner()[CIPHERTEXT_NONCE];

        if let Ok(pk) = AffinePoint::new(pk_x, pk_y) {
            // Generate the secret key
            let sk = SecretKey::from_dh_exchange(&pk, sk)?;
            let (secret_key_x, secret_key_y) = sk.get_coordinates();

            // Init poseidon sponge state
            let mut poseidon_state = poseidon_hash_many(&vec![
                secret_key_x,
                secret_key_y,
                encrypt_nonce,
                Felt::from(PLAINTEXT_NUM),
            ]);

            // Decrypt
            let mut msg = vec![];
            for cipher_element in &self.inner()[0..PLAINTEXT_NUM] {
                let msg_element = *cipher_element - poseidon_state;
                msg.push(msg_element);
                poseidon_state = poseidon_hash(*cipher_element, secret_key_x);
            }

            if mac != poseidon_state {
                return Err(CairoError::DecryptionFailure);
            }

            Ok(msg)
        } else {
            Err(CairoError::InvalidPublicKey)
        }
    }

    pub fn from_bytes(input_vec: Vec<Vec<u8>>) -> Result<Self, CairoError> {
        let cipher_felt = bytes_to_felt_vec(input_vec)?;
        let cipher: [Felt; CIPHERTEXT_NUM] = cipher_felt
            .try_into()
            .map_err(|_| CairoError::InvalidCiphertextLength)?;
        Ok(Self(cipher))
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
    pub fn from_dh_exchange(pk: &AffinePoint, sk: &Felt) -> Result<Self, CairoError> {
        let pk_projective =
            ProjectivePoint::try_from(pk.clone()).map_err(|_| CairoError::InvalidAffinePoint)?;
        let key = (&pk_projective * *sk)
            .to_affine()
            .map_err(|_| CairoError::InvalidDHKey)?;
        Ok(Self(key))
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
    let cipher = Ciphertext::encrypt(&messages, &pk, &sender_sk, &encrypt_nonce).unwrap();

    // Decryption
    let decryption = cipher.decrypt(&Felt::ONE).unwrap();

    let padded_plaintext = Plaintext::padding(&messages);
    assert_eq!(padded_plaintext.to_vec(), decryption);
}
