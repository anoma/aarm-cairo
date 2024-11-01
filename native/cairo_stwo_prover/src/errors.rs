use rustler::{Encoder, Env, Term};

#[derive(Debug)]
pub(crate) enum StwoProveError {
    TraceParseError(String),
    MemoryParseError(String),
    PublicInputParseError(String),
    ProofGenerationError(String),
    EncodingError(String),
}

impl std::fmt::Display for StwoProveError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            StwoProveError::TraceParseError(msg) => {
                write!(f, "Failed to parse trace data: {}", msg)
            }
            StwoProveError::MemoryParseError(msg) => {
                write!(f, "Failed to parse memory data: {}", msg)
            }
            StwoProveError::PublicInputParseError(msg) => {
                write!(f, "Failed to parse public input: {}", msg)
            }
            StwoProveError::ProofGenerationError(msg) => {
                write!(f, "Proof generation failed: {}", msg)
            }
            StwoProveError::EncodingError(msg) => {
                write!(f, "Failed to encode output: {}", msg)
            }
        }
    }
}

impl Encoder for StwoProveError {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.to_string().encode(env)
    }
}
