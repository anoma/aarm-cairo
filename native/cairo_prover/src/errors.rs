use rustler::{Encoder, Env, Term};

#[derive(Debug)]
pub(crate) enum CairoProveError {
    RegisterStatesError(String),
    CairoMemoryError(String),
    ProofGenerationError(String),
    PublicInputError(String),
    EncodingError(String),
}

impl std::fmt::Display for CairoProveError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CairoProveError::RegisterStatesError(msg) => {
                write!(f, "Register states error: {}", msg)
            }
            CairoProveError::CairoMemoryError(msg) => write!(f, "Cairo memory error: {}", msg),
            CairoProveError::ProofGenerationError(msg) => {
                write!(f, "Proof generation failed: {}", msg)
            }
            CairoProveError::PublicInputError(msg) => write!(f, "Public input error: {}", msg),
            CairoProveError::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
        }
    }
}

impl Encoder for CairoProveError {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.to_string().encode(env)
    }
}

#[derive(Debug)]
pub(crate) enum CairoVerifyError {
    ProofDecodingError(String),
    PublicInputDecodingError(String),
}

impl std::fmt::Display for CairoVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CairoVerifyError::ProofDecodingError(msg) => write!(f, "Proof decoding error: {}", msg),
            CairoVerifyError::PublicInputDecodingError(msg) => {
                write!(f, "Public input decoding error: {}", msg)
            }
        }
    }
}

impl Encoder for CairoVerifyError {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.to_string().encode(env)
    }
}

#[derive(Debug)]
pub(crate) enum CairoGetOutputError {
    DecodingError(String),
    SegmentNotFound,
    AddressNotFound(u64),
}

impl std::fmt::Display for CairoGetOutputError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CairoGetOutputError::DecodingError(msg) => write!(f, "Decoding error: {}", msg),
            CairoGetOutputError::SegmentNotFound => {
                write!(f, "Output segment not found in memory segments")
            }
            CairoGetOutputError::AddressNotFound(addr) => {
                write!(f, "Address {} not found in public memory", addr)
            }
        }
    }
}

impl Encoder for CairoGetOutputError {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.to_string().encode(env)
    }
}

#[derive(Debug)]
pub(crate) enum CairoSignError {
    SignatureGenerationError(String),
}

impl std::fmt::Display for CairoSignError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CairoSignError::SignatureGenerationError(msg) => {
                write!(f, "Binding Signature generation error: {}", msg)
            }
        }
    }
}

impl Encoder for CairoSignError {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.to_string().encode(env)
    }
}

#[derive(Debug)]
pub enum CairoBindingSigVerifyError {
    InputError,
    VerificationError,
}

impl std::fmt::Display for CairoBindingSigVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CairoBindingSigVerifyError::InputError => write!(f, "Invalid input data"),
            CairoBindingSigVerifyError::VerificationError => {
                write!(f, "Signature verification failed")
            }
        }
    }
}

impl Encoder for CairoBindingSigVerifyError {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.to_string().encode(env)
    }
}

#[derive(Debug)]
pub enum CairoBindingSigError {
    KeyGenerationError,
}

impl std::fmt::Display for CairoBindingSigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CairoBindingSigError::KeyGenerationError => write!(f, "Error generating key"),
        }
    }
}

impl Encoder for CairoBindingSigError {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.to_string().encode(env)
    }
}
