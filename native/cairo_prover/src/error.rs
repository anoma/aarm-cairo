use bincode::error::{DecodeError, EncodeError};
use rustler::{Encoder, Env, Term};
use serde_json::error::Error as JsonError;
use starknet_crypto::SignError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CairoError {
    #[error("Inputs should not be empty")]
    EmptyInputs,
    #[error("Bytes should be a multiple of 24 for trace or 40 for memory")]
    CairoImportError,
    #[error("Parse public input error: {0}")]
    ParsePublicInputError(String),
    #[error("Proving error")]
    ProvingError,
    #[error(transparent)]
    EncodeError(#[from] EncodeError),
    #[error(transparent)]
    DecodeError(#[from] DecodeError),
    #[error("Segment not found in memory(public input)")]
    SegmentNotFound,
    #[error("Address({0}) not found in memory(public input)")]
    AddressNotFound(u64),
    #[error(transparent)]
    SignError(#[from] SignError),
    #[error("Bytes should be a multiple of 32")]
    InvalidInputs,
    #[error("Invalid finite field: 32 bytes needed")]
    InvalidFiniteField,
    #[error("Invalid Point")]
    InvalidAffinePoint,
    #[error("Invalid signature: 64 bytes needed")]
    InvalidSignatureFormat,
    #[error("Signature verification failed")]
    SigVerifyError,
    #[error(transparent)]
    JsonError(#[from] JsonError),
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid DH key")]
    InvalidDHKey,
    #[error("Invalid mac in decryption")]
    DecryptionFailure,
    #[error("The length of ciphertext is not correct")]
    InvalidCiphertextLength,
}

impl Encoder for CairoError {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.to_string().encode(env)
    }
}

impl From<CairoError> for rustler::Error {
    fn from(e: CairoError) -> Self {
        rustler::Error::Term(Box::new(e))
    }
}
